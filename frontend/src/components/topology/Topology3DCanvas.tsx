"use client";

import React, { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import type { TopologyNode, TopologyEdge } from "@/types";

interface Topology3DCanvasProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  selectedNode: TopologyNode | null;
  onSelectNode: (node: TopologyNode) => void;
}

interface ProjectedNode {
  id: string;
  x: number;
  y: number;
  visible: boolean;
  node: TopologyNode;
}

interface ProjectedEdge {
  id: string;
  x: number;
  y: number;
  visible: boolean;
  edge: TopologyEdge;
}

export default function Topology3DCanvas({
  nodes,
  edges,
  selectedNode,
  onSelectNode
}: Topology3DCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasContainerRef = useRef<HTMLDivElement>(null);
  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const controlsRef = useRef<OrbitControls | null>(null);

  const [projectedNodes, setProjectedNodes] = useState<ProjectedNode[]>([]);
  const [projectedEdges, setProjectedEdges] = useState<ProjectedEdge[]>([]);

  // Store mesh references
  const nodeMeshesRef = useRef<Map<string, THREE.Group>>(new Map());
  const edgeLinesRef = useRef<THREE.Object3D[]>([]);
  const packetSpheresRef = useRef<{ mesh: THREE.Mesh; src: THREE.Vector3; dst: THREE.Vector3; progress: number; speed: number }[]>([]);

  const getDeviceIconSymbol = (type: string) => {
    switch (type) {
      case "Router":
      case "Gateway Router":
        return "🌐";
      case "Monitoring Server":
        return "🛡️";
      case "Server":
        return "🗄️";
      case "Desktop":
      case "Workstation":
        return "🖥️";
      case "Laptop":
        return "💻";
      case "Phone":
      case "Mobile":
      case "Mobile Phone":
      case "Android Phone":
      case "iPhone":
        return "📱";
      case "Tablet":
        return "📲";
      case "PLC":
        return "⚙️";
      case "Smart Meter":
        return "⚡";
      case "Camera":
        return "📹";
      case "Printer":
        return "🖨️";
      case "IoT Device":
        return "🔌";
      case "Switch":
        return "🔀";
      case "Firewall":
        return "🧱";
      case "Internet":
        return "☁️";
      default:
        return "❓";
    }
  };

  const getStatusColor = (status: string, risk: string) => {
    if (status === "Monitoring Server") return "#3b82f6"; // Blue
    if (status === "Under Attack" || risk === "Critical" || risk === "High") return "#ef4444"; // Red
    if (status === "Busy" || risk === "Medium") return "#f59e0b"; // Yellow
    if (status === "Offline") return "#64748b"; // Slate
    return "#10b981"; // Green
  };

  // Create custom procedural 3D Models per device category
  const createDevice3DModel = (node: TopologyNode): THREE.Group => {
    const group = new THREE.Group();
    group.userData = {
      nodeId: node.id,
      isRouter: node.is_router,
      isInternet: node.id === "internet" || node.device_type === "Internet",
      isMonitoring: node.is_monitoring_server
    };

    const isAttacked = node.is_attacker || node.is_victim || node.risk_level === "Critical" || node.status === "Under Attack";
    let baseColor = 0x10b981; // Green Online

    if (node.is_monitoring_server) baseColor = 0x3b82f6; // Blue
    else if (node.is_router) baseColor = 0x00d4ff; // Cyan
    else if (node.id === "internet" || node.device_type === "Internet") baseColor = 0x8b5cf6; // Purple
    else if (isAttacked) baseColor = 0xef4444; // Red
    else if (node.status === "Busy") baseColor = 0xf59e0b; // Yellow

    const mainMaterial = new THREE.MeshStandardMaterial({
      color: baseColor,
      roughness: 0.2,
      metalness: 0.7,
      emissive: baseColor,
      emissiveIntensity: isAttacked ? 0.6 : 0.3
    });

    if (node.id === "internet" || node.device_type === "Internet") {
      const sphereGeo = new THREE.IcosahedronGeometry(1.6, 2);
      const cloudMesh = new THREE.Mesh(sphereGeo, mainMaterial);
      cloudMesh.name = "main";
      group.add(cloudMesh);

      const wireMat = new THREE.MeshBasicMaterial({ color: 0xc084fc, wireframe: true });
      const wireMesh = new THREE.Mesh(new THREE.IcosahedronGeometry(1.8, 1), wireMat);
      wireMesh.name = "spinner";
      group.add(wireMesh);
    } else if (node.is_router) {
      const bodyGeo = new THREE.BoxGeometry(2.4, 0.6, 1.8);
      const bodyMesh = new THREE.Mesh(bodyGeo, mainMaterial);
      bodyMesh.name = "main";
      group.add(bodyMesh);

      const antGeo = new THREE.CylinderGeometry(0.06, 0.06, 1.5, 8);
      const antMat = new THREE.MeshStandardMaterial({ color: 0x334155, metalness: 0.9 });
      const ant1 = new THREE.Mesh(antGeo, antMat);
      ant1.position.set(-0.8, 0.8, -0.6);
      group.add(ant1);

      const ant2 = new THREE.Mesh(antGeo, antMat);
      ant2.position.set(0.8, 0.8, -0.6);
      group.add(ant2);

      const ringGeo = new THREE.TorusGeometry(2.2, 0.06, 16, 32);
      const ringMat = new THREE.MeshBasicMaterial({ color: 0x00d4ff, wireframe: true });
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      ringMesh.name = "spinner";
      ringMesh.rotation.x = Math.PI / 2;
      group.add(ringMesh);
    } else if (node.is_monitoring_server || node.device_type === "Server") {
      const rackGeo = new THREE.BoxGeometry(1.5, 2.2, 1.5);
      const rackMesh = new THREE.Mesh(rackGeo, mainMaterial);
      rackMesh.name = "main";
      group.add(rackMesh);

      const ledGeo = new THREE.BoxGeometry(1.3, 0.1, 0.05);
      const ledMat = new THREE.MeshBasicMaterial({ color: 0x60a5fa });
      for (let i = 0; i < 4; i++) {
        const led = new THREE.Mesh(ledGeo, ledMat);
        led.position.set(0, -0.6 + i * 0.4, 0.78);
        group.add(led);
      }
    } else if (node.device_type === "Laptop" || node.device_type === "Workstation") {
      const baseGeo = new THREE.BoxGeometry(1.6, 0.15, 1.2);
      const baseMesh = new THREE.Mesh(baseGeo, mainMaterial);
      baseMesh.name = "main";
      group.add(baseMesh);

      const screenGeo = new THREE.BoxGeometry(1.6, 1.1, 0.1);
      const screenMesh = new THREE.Mesh(screenGeo, mainMaterial);
      screenMesh.position.set(0, 0.6, -0.55);
      screenMesh.rotation.x = -0.2;
      group.add(screenMesh);
    } else if (
      node.device_type === "Phone" ||
      node.device_type === "Mobile" ||
      node.device_type === "Mobile Phone" ||
      node.device_type === "Android Phone" ||
      node.device_type === "iPhone" ||
      node.device_type === "Tablet"
    ) {
      const phoneGeo = new THREE.BoxGeometry(0.8, 1.5, 0.1);
      const phoneMesh = new THREE.Mesh(phoneGeo, mainMaterial);
      phoneMesh.name = "main";
      phoneMesh.rotation.x = -0.3;
      group.add(phoneMesh);
    } else {
      const boxGeo = new THREE.BoxGeometry(1.3, 1.3, 1.3);
      const boxMesh = new THREE.Mesh(boxGeo, mainMaterial);
      boxMesh.name = "main";
      group.add(boxMesh);
    }

    return group;
  };

  useEffect(() => {
    if (!canvasContainerRef.current) return;
    const canvasContainer = canvasContainerRef.current;
    const width = containerRef.current?.clientWidth || 800;
    const height = containerRef.current?.clientHeight || 500;

    // 1. Initialize 3D Scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x070d19);
    scene.fog = new THREE.FogExp2(0x070d19, 0.012);
    sceneRef.current = scene;

    // 2. Camera Setup
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 15, 28);
    cameraRef.current = camera;

    // 3. WebGL Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;

    canvasContainer.innerHTML = "";
    canvasContainer.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // 4. Orbit Controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.maxPolarAngle = Math.PI / 2 + 0.1;
    controls.minDistance = 4;
    controls.maxDistance = 70;
    controlsRef.current = controls;

    // 5. Lighting Setup
    const ambientLight = new THREE.AmbientLight(0x60a5fa, 0.8);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0x00d4ff, 1.4);
    dirLight.position.set(15, 25, 15);
    dirLight.castShadow = true;
    scene.add(dirLight);

    const redSpot = new THREE.PointLight(0xef4444, 1.5, 30);
    redSpot.position.set(0, 12, 0);
    scene.add(redSpot);

    // 6. 3D Cyber Floor Grid
    const gridHelper = new THREE.GridHelper(44, 44, 0x00d4ff, 0x1e2f50);
    gridHelper.position.y = -0.01;
    scene.add(gridHelper);

    // Raycaster for Node selection & Dragging
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();
    let isDraggingNode = false;
    let draggedNodeId: string | null = null;
    const dragPlane = new THREE.Plane(new THREE.Vector3(0, 1, 0), 0);
    const planeIntersect = new THREE.Vector3();

    const getPointerPos = (e: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
    };

    const onMouseDown = (e: MouseEvent) => {
      if (e.button !== 0) return;
      getPointerPos(e);
      raycaster.setFromCamera(mouse, camera);

      const interactiveObjects: THREE.Object3D[] = [];
      nodeMeshesRef.current.forEach((group) => {
        group.traverse((child) => {
          if ((child as THREE.Mesh).isMesh) interactiveObjects.push(child);
        });
      });

      const intersects = raycaster.intersectObjects(interactiveObjects);
      if (intersects.length > 0) {
        let obj: THREE.Object3D | null = intersects[0].object;
        while (obj && !obj.userData?.nodeId) {
          obj = obj.parent;
        }
        if (obj && obj.userData?.nodeId) {
          const nodeId = obj.userData.nodeId;
          const foundNode = nodes.find((n) => n.id === nodeId);
          if (foundNode) {
            onSelectNode(foundNode);
            isDraggingNode = true;
            draggedNodeId = nodeId;
            controls.enabled = false;
          }
        }
      }
    };

    const onDblClick = (e: MouseEvent) => {
      getPointerPos(e);
      raycaster.setFromCamera(mouse, camera);

      const interactiveObjects: THREE.Object3D[] = [];
      nodeMeshesRef.current.forEach((group) => {
        group.traverse((child) => {
          if ((child as THREE.Mesh).isMesh) interactiveObjects.push(child);
        });
      });

      const intersects = raycaster.intersectObjects(interactiveObjects);
      if (intersects.length > 0) {
        let obj: THREE.Object3D | null = intersects[0].object;
        while (obj && !obj.userData?.nodeId) {
          obj = obj.parent;
        }
        if (obj) {
          const targetPos = obj.position.clone();
          controls.target.copy(targetPos);
          camera.position.set(targetPos.x, targetPos.y + 6, targetPos.z + 10);
        }
      }
    };

    const onMouseMove = (e: MouseEvent) => {
      if (isDraggingNode && draggedNodeId) {
        getPointerPos(e);
        raycaster.setFromCamera(mouse, camera);
        if (raycaster.ray.intersectPlane(dragPlane, planeIntersect)) {
          const group = nodeMeshesRef.current.get(draggedNodeId);
          if (group) {
            group.position.x = planeIntersect.x;
            group.position.z = planeIntersect.z;
          }
        }
      }
    };

    const onMouseUp = () => {
      isDraggingNode = false;
      draggedNodeId = null;
      controls.enabled = true;
    };

    const domElem = renderer.domElement;
    domElem.addEventListener("mousedown", onMouseDown);
    domElem.addEventListener("dblclick", onDblClick);
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);

    // 7. Animation Loop & 3D to 2D Screen Projection
    let animationFrameId: number;
    let frameCount = 0;

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      controls.update();

      // Rotate accent spinners
      nodeMeshesRef.current.forEach((group) => {
        const spinner = group.getObjectByName("spinner");
        if (spinner) spinner.rotation.y += 0.015;
      });

      // Animate 3D Traffic Packets along edges
      packetSpheresRef.current.forEach((pkt) => {
        pkt.progress += pkt.speed;
        if (pkt.progress > 1) pkt.progress = 0;
        pkt.mesh.position.lerpVectors(pkt.src, pkt.dst, pkt.progress);
      });

      renderer.render(scene, camera);

      // Project 3D Node & Edge coordinates to 2D Screen Badges (throttle every 2 frames for 60 FPS performance)
      frameCount++;
      if (frameCount % 2 === 0 && containerRef.current && cameraRef.current) {
        const w = containerRef.current.clientWidth;
        const h = containerRef.current.clientHeight;

        const projNodes: ProjectedNode[] = [];
        nodeMeshesRef.current.forEach((group, id) => {
          const foundNode = nodes.find((n) => n.id === id);
          if (foundNode) {
            const worldPos = group.position.clone().add(new THREE.Vector3(0, 1.8, 0));
            worldPos.project(cameraRef.current!);
            const screenX = ((worldPos.x + 1) * w) / 2;
            const screenY = ((-worldPos.y + 1) * h) / 2;
            projNodes.push({
              id,
              x: screenX,
              y: screenY,
              visible: worldPos.z < 1 && screenX >= 0 && screenX <= w && screenY >= 0 && screenY <= h,
              node: foundNode
            });
          }
        });
        setProjectedNodes(projNodes);

        // Project Edge midpoints for traffic telemetry badges
        const projEdges: ProjectedEdge[] = [];
        edges.forEach((edge, idx) => {
          const srcGroup = nodeMeshesRef.current.get(edge.source);
          const dstGroup = nodeMeshesRef.current.get(edge.target);
          if (srcGroup && dstGroup) {
            const midPos = srcGroup.position.clone().lerp(dstGroup.position, 0.5);
            midPos.project(cameraRef.current!);
            const screenX = ((midPos.x + 1) * w) / 2;
            const screenY = ((-midPos.y + 1) * h) / 2;
            projEdges.push({
              id: `edge-${idx}`,
              x: screenX,
              y: screenY,
              visible: midPos.z < 1 && screenX >= 0 && screenX <= w && screenY >= 0 && screenY <= h,
              edge
            });
          }
        });
        setProjectedEdges(projEdges);
      }
    };
    animate();

    const handleResize = () => {
      if (!containerRef.current || !rendererRef.current || !cameraRef.current) return;
      const w = containerRef.current.clientWidth;
      const h = containerRef.current.clientHeight;
      cameraRef.current.aspect = w / h;
      cameraRef.current.updateProjectionMatrix();
      rendererRef.current.setSize(w, h);
    };
    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
      domElem.removeEventListener("mousedown", onMouseDown);
      domElem.removeEventListener("dblclick", onDblClick);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
      cancelAnimationFrame(animationFrameId);
      if (canvasContainer && canvasContainer.contains(renderer.domElement)) {
        canvasContainer.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [nodes, edges]);

  // Sync 3D Positions
  useEffect(() => {
    const scene = sceneRef.current;
    if (!scene) return;

    edgeLinesRef.current.forEach((l) => scene.remove(l));
    edgeLinesRef.current = [];

    packetSpheresRef.current.forEach((p) => scene.remove(p.mesh));
    packetSpheresRef.current = [];

    const nodePositions: Map<string, THREE.Vector3> = new Map();
    const subnetNodes = nodes.filter((n) => n.id !== "internet" && n.device_type !== "Internet" && !n.is_router);
    const subnetCount = subnetNodes.length || 1;

    nodes.forEach((node) => {
      let group = nodeMeshesRef.current.get(node.id);
      let pos = new THREE.Vector3();

      if (node.id === "internet" || node.device_type === "Internet") {
        pos.set(0, 6.5, -9);
      } else if (node.is_router) {
        pos.set(0, 3.8, -3.5);
      } else {
        const index = subnetNodes.findIndex((n) => n.id === node.id);
        const startX = -13;
        const endX = 13;
        const step = subnetCount > 1 ? (endX - startX) / (subnetCount - 1) : 0;
        const posX = subnetCount === 1 ? 0 : startX + index * step;
        pos.set(posX, 1.2, 5.5);
      }

      if (!group) {
        group = createDevice3DModel(node);
        group.position.copy(pos);
        scene.add(group);
        nodeMeshesRef.current.set(node.id, group);
      } else {
        pos = group.position;
      }

      nodePositions.set(node.id, pos);
    });

    nodeMeshesRef.current.forEach((group, id) => {
      if (!nodes.some((n) => n.id === id)) {
        scene.remove(group);
        nodeMeshesRef.current.delete(id);
      }
    });

    edges.forEach((edge) => {
      const srcPos = nodePositions.get(edge.source);
      const dstPos = nodePositions.get(edge.target);
      if (!srcPos || !dstPos) return;

      const color = edge.is_attack ? 0xef4444 : 0x00d4ff;

      if (edge.is_attack) {
        const curve = new THREE.LineCurve3(srcPos, dstPos);
        const tubeGeo = new THREE.TubeGeometry(curve, 20, 0.15, 8, false);
        const tubeMat = new THREE.MeshStandardMaterial({
          color: 0xef4444,
          emissive: 0xef4444,
          emissiveIntensity: 0.8,
          roughness: 0.1
        });
        const tubeMesh = new THREE.Mesh(tubeGeo, tubeMat);
        scene.add(tubeMesh);
        edgeLinesRef.current.push(tubeMesh);

        if (edge.is_blocked) {
          const lockGeo = new THREE.BoxGeometry(0.6, 0.6, 0.3);
          const lockMat = new THREE.MeshStandardMaterial({ color: 0xf59e0b, emissive: 0xf59e0b, emissiveIntensity: 0.5 });
          const lockMesh = new THREE.Mesh(lockGeo, lockMat);
          lockMesh.position.lerpVectors(srcPos, dstPos, 0.5);
          scene.add(lockMesh);
          edgeLinesRef.current.push(lockMesh);
        }
      } else {
        const points = [srcPos.clone(), dstPos.clone()];
        const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
        const lineMat = new THREE.LineBasicMaterial({ color: color, linewidth: 1.5 });
        const line = new THREE.Line(lineGeo, lineMat);
        scene.add(line);
        edgeLinesRef.current.push(line);
      }

      if (!edge.is_blocked) {
        const pps = edge.packets_per_second || 10;
        const pktSpeed = Math.max(0.008, Math.min(0.04, pps * 0.0005));

        const pktGeo = new THREE.SphereGeometry(edge.is_attack ? 0.3 : 0.2, 12, 12);
        const pktMat = new THREE.MeshBasicMaterial({ color: color });
        const pktMesh = new THREE.Mesh(pktGeo, pktMat);
        scene.add(pktMesh);

        packetSpheresRef.current.push({
          mesh: pktMesh,
          src: srcPos.clone(),
          dst: dstPos.clone(),
          progress: Math.random(),
          speed: pktSpeed
        });
      }
    });
  }, [nodes, edges]);

  const resetCamera = () => {
    if (cameraRef.current && controlsRef.current) {
      cameraRef.current.position.set(0, 15, 28);
      controlsRef.current.target.set(0, 0, 0);
      controlsRef.current.update();
    }
  };

  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        height: "100%",
        position: "relative",
        cursor: "grab"
      }}
    >
      <div ref={canvasContainerRef} style={{ width: "100%", height: "100%", position: "absolute", top: 0, left: 0 }} />
      {/* Overlay 3D Controls Hint & Reset Camera */}
      <div
        style={{
          position: "absolute",
          top: 12,
          left: 12,
          display: "flex",
          gap: 10,
          alignItems: "center",
          zIndex: 10
        }}
      >
        <div
          style={{
            background: "rgba(13, 21, 39, 0.9)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: "6px 12px",
            fontSize: 11,
            color: "var(--text-muted)",
            pointerEvents: "none"
          }}
        >
          🖱️ <strong>Left Drag</strong> Rotate | <strong>Drag 3D Node</strong> Move | <strong>Double-Click Node</strong> Focus | <strong>Scroll</strong> Zoom
        </div>

        <button
          className="btn btn-secondary"
          onClick={resetCamera}
          style={{ fontSize: 11, padding: "5px 10px", height: "auto" }}
        >
          🎯 Reset Camera
        </button>
      </div>

      {/* Floating 3D Device Badges Overlay showing Device Type & Host Info */}
      {projectedNodes.map((p) => {
        if (!p.visible) return null;
        const isDisconnected = p.node.status === "Disconnected" || p.node.status === "Offline";
        const color = isDisconnected ? "#64748b" : getStatusColor(p.node.status, p.node.risk_level);
        const isSelected = selectedNode?.id === p.node.id;
        const confidence = p.node.classification_confidence ?? 95;
        const displayType = confidence < 80 ? "UNKNOWN DEVICE" : p.node.device_type;

        return (
          <div
            key={`badge-${p.id}`}
            onClick={() => onSelectNode(p.node)}
            style={{
              position: "absolute",
              left: p.x,
              top: p.y,
              transform: "translate(-50%, -100%)",
              background: "rgba(13, 21, 39, 0.94)",
              border: `1px solid ${isSelected ? "var(--accent-cyan)" : color}`,
              borderRadius: 6,
              padding: "5px 10px",
              fontSize: 11,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 2,
              cursor: "pointer",
              boxShadow: `0 0 12px ${color}40`,
              zIndex: isSelected ? 20 : 5,
              opacity: isDisconnected ? 0.45 : 1,
              pointerEvents: "auto"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontWeight: 700, color: "var(--text-primary)" }}>
              <span>{getDeviceIconSymbol(displayType)}</span>
              <span>{displayType}</span>
              <span style={{ fontSize: 9, color: "var(--accent-cyan)", fontWeight: 600 }}>({confidence.toFixed(0)}%)</span>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: color }} />
            </div>

            <div style={{ fontSize: 10, color: "var(--text-muted)", display: "flex", gap: 6, alignItems: "center" }}>
              <span>{p.node.label}</span>
              <span>•</span>
              <span style={{ fontFamily: "var(--font-mono)" }}>{p.node.ip}</span>
            </div>

            <div style={{ fontSize: 9, color: "var(--text-secondary)", display: "flex", gap: 6, marginTop: 1 }}>
              <span>{p.node.connection_type === "WiFi" ? `📶 WiFi (${p.node.signal_strength_dbm || -62}dBm)` : "🔌 Ethernet"}</span>
              <span>•</span>
              <span>⬇️ {p.node.download_mbps || 0.12}Mbps</span>
            </div>

            {isDisconnected && (
              <div style={{ fontSize: 9, color: "var(--color-critical)", fontWeight: 700, marginTop: 2 }}>
                ⚫ Disconnected {p.node.disconnected_for_seconds ? `for ${Math.floor(p.node.disconnected_for_seconds / 60)}m ${Math.floor(p.node.disconnected_for_seconds % 60)}s` : ""}
              </div>
            )}
          </div>
        );
      })}

      {/* Floating 3D Traffic Telemetry Badges Overlay showing How Traffic is Moving */}
      {projectedEdges.map((p) => {
        if (!p.visible) return null;
        const isAtk = p.edge.is_attack;
        const isBlk = p.edge.is_blocked;

        return (
          <div
            key={`edge-badge-${p.id}`}
            style={{
              position: "absolute",
              left: p.x,
              top: p.y,
              transform: "translate(-50%, -50%)",
              background: isAtk ? "rgba(153, 27, 27, 0.9)" : "rgba(15, 23, 42, 0.85)",
              border: `1px solid ${isAtk ? "var(--color-critical)" : "rgba(0, 212, 255, 0.4)"}`,
              borderRadius: 4,
              padding: "2px 6px",
              fontSize: 10,
              color: "#ffffff",
              pointerEvents: "none",
              zIndex: isAtk ? 15 : 4,
              display: "flex",
              alignItems: "center",
              gap: 4
            }}
          >
            {isBlk ? (
              <span>🔒 Blocked Traffic Vector</span>
            ) : isAtk ? (
              <span>⚡ 🔴 ATTACK FLOW: {p.edge.packets_per_second || 44} pkt/s</span>
            ) : (
              <span>⚡ {p.edge.source} ➔ {p.edge.target} ({p.edge.packets_per_second || 15} pkt/s)</span>
            )}
          </div>
        );
      })}
    </div>
  );
}
