"""
Real AI/ML network anomaly detection engine using PyTorch.
Implements an Autoencoder for anomaly detection and an LSTM for threat forecasting.
Trains online on the local network's traffic baseline during startup.
"""

import asyncio
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from collections import deque
from database import insert_prediction
from services.log_manager import log_manager
from services.packet_capture import packet_capture


# ────────────────────────────────────────────
# PyTorch Model Definitions
# ────────────────────────────────────────────

class NetworkAutoencoder(nn.Module):
    """Autoencoder to detect network anomalies based on reconstruction error."""
    def __init__(self, input_dim: int):
        super(NetworkAutoencoder, self).__init__()
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 8),
            nn.ReLU(),
            nn.Linear(8, 4),
            nn.ReLU()
        )
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.ReLU(),
            nn.Linear(8, input_dim),
            nn.Sigmoid()  # Assumes inputs scaled between 0 and 1
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class ThreatLSTM(nn.Module):
    """LSTM to predict future threat scores from a history sequence."""
    def __init__(self, sequence_length: int):
        super(ThreatLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size=1, hidden_size=16, num_layers=1, batch_first=True)
        self.fc = nn.Sequential(
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 3)  # Forecasts 10s, 30s, 60s
        )

    def forward(self, x):
        # x shape: (batch_size, seq_len, 1)
        out, _ = self.lstm(x)
        # Take last time step output
        last_out = out[:, -1, :]
        return self.fc(last_out)


# ────────────────────────────────────────────
# AI Engine Service
# ────────────────────────────────────────────

class AIEngineService:
    """Manages the AI pipeline: baseline collection, online training, inference, and forecasting."""

    def __init__(self):
        self.is_running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._subscribers: List[Callable] = []

        # Feature configuration
        self.feature_names = [
            "pps", "bps", "unique_ips", "tcp_ratio", "udp_ratio", 
            "icmp_ratio", "syn_ratio", "distinct_ports"
        ]
        self.input_dim = len(self.feature_names)

        # Baseline training settings
        self.baseline_duration_seconds = 120  # Collect for 2 mins
        self.inference_interval = 5  # Infer every 5s
        
        self.baseline_features: List[List[float]] = []
        self.is_trained = False
        self.model_status = "Offline"  # "Offline", "Collecting Baseline", "Active"
        
        # PyTorch models
        self.autoencoder = NetworkAutoencoder(self.input_dim)
        self.lstm = ThreatLSTM(sequence_length=10)
        self.ae_optimizer = optim.Adam(self.autoencoder.parameters(), lr=0.01)
        self.lstm_optimizer = optim.Adam(self.lstm.parameters(), lr=0.01)
        self.criterion = nn.MSELoss()

        # Scaling parameters (calculated from baseline)
        self.feature_min = np.zeros(self.input_dim)
        self.feature_max = np.ones(self.input_dim)
        self.anomaly_threshold = 0.05

        # Rolling buffers for LSTM sequence
        self.threat_history = deque(maxlen=20)
        self.latest_result: Dict = {
            "timestamp": datetime.now().isoformat(),
            "threat_probability": 0.0,
            "confidence": 95.0,
            "predicted_attack_type": "None",
            "expected_severity": "Low",
            "reason": "System starting up...",
            "model_status": "Offline",
            "anomaly_score": 0.0,
            "forecast_10s": 0.0,
            "forecast_30s": 0.0,
            "forecast_60s": 0.0,
            "trend": "stable"
        }

    def subscribe(self, callback: Callable):
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    async def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        self.is_running = True
        self.model_status = "Collecting Baseline"
        self.latest_result["model_status"] = "Collecting Baseline"
        asyncio.ensure_future(self._ai_loop())
        await log_manager.log("AIEngine", "INFO", "AI Prediction Engine starting, collecting baseline network profile...")

    async def stop(self):
        self.is_running = False
        self.model_status = "Offline"
        self.latest_result["model_status"] = "Offline"
        await log_manager.log("AIEngine", "INFO", "AI Prediction Engine stopped")

    def _extract_features(self, packets: List[Dict], interval_seconds: float) -> List[float]:
        """Convert a batch of raw packet dicts into structured normalized features."""
        if not packets:
            return [0.0] * self.input_dim

        total_bytes = sum(pkt["size"] for pkt in packets)
        pps = len(packets) / interval_seconds
        bps = total_bytes / interval_seconds

        unique_ips = len(set(pkt["src_ip"] for pkt in packets) | set(pkt["dst_ip"] for pkt in packets))
        distinct_ports = len(set(pkt["src_port"] for pkt in packets if pkt["src_port"]) | 
                             set(pkt["dst_port"] for pkt in packets if pkt["dst_port"]))

        tcp_count = sum(1 for pkt in packets if pkt["protocol"] == "TCP")
        udp_count = sum(1 for pkt in packets if pkt["protocol"] == "UDP")
        icmp_count = sum(1 for pkt in packets if pkt["protocol"] == "ICMP")

        tcp_ratio = tcp_count / len(packets)
        udp_ratio = udp_count / len(packets)
        icmp_ratio = icmp_count / len(packets)

        # SYN ratio to help detect Floods
        syn_count = sum(1 for pkt in packets if pkt["protocol"] == "TCP" and "S" in pkt["tcp_flags"])
        syn_ratio = syn_count / tcp_count if tcp_count > 0 else 0.0

        return [
            pps, bps, float(unique_ips), tcp_ratio, udp_ratio, 
            icmp_ratio, syn_ratio, float(distinct_ports)
        ]

    def _scale_features(self, features: List[float]) -> np.ndarray:
        """MinMax scaling to range [0, 1]."""
        arr = np.array(features)
        denom = self.feature_max - self.feature_min
        # Prevent division by zero
        denom[denom == 0] = 1.0
        scaled = (arr - self.feature_min) / denom
        return np.clip(scaled, 0.0, 1.0)

    def _train_autoencoder(self, data: List[List[float]]):
        """Train Autoencoder on normal baseline data."""
        tensor_data = torch.FloatTensor(data)
        epochs = 200
        
        for epoch in range(epochs):
            self.autoencoder.train()
            self.ae_optimizer.zero_grad()
            outputs = self.autoencoder(tensor_data)
            loss = self.criterion(outputs, tensor_data)
            loss.backward()
            self.ae_optimizer.step()

        # Compute reconstruction error baseline
        self.autoencoder.eval()
        with torch.no_grad():
            preds = self.autoencoder(tensor_data)
            losses = torch.mean((preds - tensor_data) ** 2, dim=1).numpy()
            self.anomaly_threshold = float(np.mean(losses) + 3 * np.std(losses))
            # Ensure safe lower bound
            if self.anomaly_threshold < 0.01:
                self.anomaly_threshold = 0.01

    def _detect_attack_type(self, features: List[float], scaled: np.ndarray) -> str:
        """Rule-based tagger helper to classify the type of anomaly/attack."""
        pps, bps, unique_ips, tcp_ratio, udp_ratio, icmp_ratio, syn_ratio, distinct_ports = features
        
        if tcp_ratio > 0.8 and syn_ratio > 0.4 and pps > 500:
            return "SYN Flood"
        if distinct_ports > 30 and pps > 50:
            return "Port Scan"
        if pps > 2000 or bps > 5000000:
            return "DDoS"
        if icmp_ratio > 0.6:
            return "ICMP Flood / Ping sweep"
        return "Anomaly / Intrusion Attempt"

    async def _ai_loop(self):
        start_time = time.time()
        
        while self.is_running:
            await asyncio.sleep(self.inference_interval)
            
            # Fetch packets captured in last interval
            raw_packets = packet_capture.get_recent_packets()
            features = self._extract_features(raw_packets, self.inference_interval)

            if not self.is_trained:
                # Add to baseline collection
                self.baseline_features.append(features)
                elapsed = time.time() - start_time
                remaining = max(0, int(self.baseline_duration_seconds - elapsed))
                
                self.latest_result["reason"] = f"Collecting normal network baseline. Please wait ({remaining}s remaining)..."
                
                if elapsed >= self.baseline_duration_seconds:
                    # Calculate scaling parameters
                    matrix = np.array(self.baseline_features)
                    self.feature_min = matrix.min(axis=0)
                    self.feature_max = matrix.max(axis=0)
                    
                    # Scale baseline features and train Autoencoder
                    scaled_baseline = [self._scale_features(f) for f in self.baseline_features]
                    self._train_autoencoder(scaled_baseline)
                    
                    self.is_trained = True
                    self.model_status = "Active"
                    self.latest_result["model_status"] = "Active"
                    await log_manager.log("AIEngine", "INFO", "Baseline profiles built. Anomaly detection system online!")
                
                # Broadcast baseline status
                self.latest_result["timestamp"] = datetime.now().isoformat()
                for callback in self._subscribers:
                    try:
                        await callback(self.latest_result)
                    except Exception:
                        pass
                continue

            # Inference phase
            scaled = self._scale_features(features)
            tensor_feat = torch.FloatTensor(scaled).unsqueeze(0)
            
            self.autoencoder.eval()
            with torch.no_grad():
                reconstructed = self.autoencoder(tensor_feat)
                loss = self.criterion(reconstructed, tensor_feat).item()

            # Threat probability calculations
            # 0 loss maps to 0%, loss equal to or above anomaly threshold maps to >= 70%
            if loss <= 0.001:
                threat_prob = 1.0
            else:
                ratio = loss / self.anomaly_threshold
                threat_prob = min(100.0, ratio * 50.0)

            # Smooth and store threat history
            self.threat_history.append(threat_prob)
            
            # Determine forecast using LSTM
            f10 = f30 = f60 = 0.0
            trend = "stable"
            
            if len(self.threat_history) >= 10:
                seq = list(self.threat_history)[-10:]
                tensor_seq = torch.FloatTensor(seq).view(1, 10, 1)
                
                self.lstm.eval()
                with torch.no_grad():
                    preds = self.lstm(tensor_seq).numpy()[0]
                    f10 = float(np.clip(preds[0], 0.0, 100.0))
                    f30 = float(np.clip(preds[1], 0.0, 100.0))
                    f60 = float(np.clip(preds[2], 0.0, 100.0))
                
                if f10 > threat_prob + 5:
                    trend = "rising"
                elif f10 < threat_prob - 5:
                    trend = "falling"

            # Classification
            attack_type = "None"
            expected_severity = "Low"
            reason = "Traffic behavior lies within normal baseline limits."
            
            if threat_prob >= 50.0:
                attack_type = self._detect_attack_type(features, scaled)
                expected_severity = "High" if threat_prob >= 75.0 else "Medium"
                reason = f"Anomalous traffic profile detected. High reconstruction error ({loss:.4f} vs threshold {self.anomaly_threshold:.4f})"
            
            self.latest_result = {
                "timestamp": datetime.now().isoformat(),
                "threat_probability": round(threat_prob, 1),
                "confidence": round(float(99.0 - (loss * 10)), 1),
                "predicted_attack_type": attack_type,
                "expected_severity": expected_severity,
                "reason": reason,
                "model_status": "Active",
                "anomaly_score": round(loss, 5),
                "forecast_10s": round(f10, 1),
                "forecast_30s": round(f30, 1),
                "forecast_60s": round(f60, 1),
                "trend": trend
            }

            # Log anomalies
            if threat_prob >= 50.0:
                await log_manager.log(
                    "AIEngine", "WARNING", 
                    f"Anomaly flagged: Prob={threat_prob:.1f}% Type={attack_type} Loss={loss:.4f}"
                )

            # Store in DB
            try:
                await insert_prediction(
                    threat_probability=threat_prob,
                    confidence=self.latest_result["confidence"],
                    predicted_attack_type=attack_type,
                    expected_severity=expected_severity,
                    reason=reason,
                    model_status="Active",
                    features_json=json.dumps(features)
                )
            except Exception:
                pass

            # Online adapt/refine LSTM model if normal data
            if threat_prob < 50.0 and len(self.threat_history) >= 11:
                hist = list(self.threat_history)
                # target sequence matches threat level shifting forward
                x_seq = torch.FloatTensor(hist[-11:-1]).view(1, 10, 1)
                y_targets = torch.FloatTensor([hist[-1], hist[-1], hist[-1]]).view(1, 3)
                
                self.lstm.train()
                self.lstm_optimizer.zero_grad()
                outputs = self.lstm(x_seq)
                l_loss = self.criterion(outputs, y_targets)
                l_loss.backward()
                self.lstm_optimizer.step()

            # Broadcast predictions
            for callback in self._subscribers:
                try:
                    await callback(self.latest_result)
                except Exception:
                    pass


# Global singleton
ai_engine = AIEngineService()
