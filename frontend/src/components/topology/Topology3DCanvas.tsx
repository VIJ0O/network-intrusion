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
    const t = (type || "").toLowerCase();
    if (t.includes("router") || t.includes("gateway")) return "🌐";
    if (t.includes("access_point") || t.includes("ap")) return "📡";
    if (t.includes("switch")) return "🔀";
    if (t.includes("firewall")) return "🧱";
    if (t.includes("monitoring")) return "🛡️";
    if (t.includes("laptop") || t.includes("notebook") || t.includes("macbook") || t.includes("thinkpad") || t.includes("ideapad")) return "💻";
    if (t.includes("phone") || t.includes("mobile") || t.includes("android") || t.includes("iphone") || t.includes("galaxy") || t.includes("pixel")) return "📱";
    if (t.includes("tablet") || t.includes("ipad")) return "📲";
    if (t.includes("desktop") || t.includes("workstation") || t.includes("optiplex") || t.includes("pc")) return "🖥️";
    if (t.includes("printer") || t.includes("print")) return "🖨️";
    if (t.includes("camera") || t.includes("cctv")) return "📹";
    if (t.includes("server")) return "🗄️";
    if (t.includes("nas")) return "💾";
    if (t.includes("iot") || t.includes("smart") || t.includes("plc") || t.includes("sensor")) return "📟";
    if (t.includes("internet") || t.includes("wan")) return "☁️";
    return "❓";
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
    else if (node.is_router || node.device_type === "router") baseColor = 0x00d4ff; // Cyan
    else if (node.id === "internet" || node.device_type === "internet") baseColor = 0x8b5cf6; // Purple
    else if (isAttacked) baseColor = 0xef4444; // Red
    else if (node.status === "Busy") baseColor = 0xf59e0b; // Yellow
    else if (node.status === "Offline" || node.status === "Disconnected") baseColor = 0x64748b; // Slate

    const mainMaterial = new THREE.MeshStandardMaterial({
      color: baseColor,
      roughness: 0.25,
      metalness: 0.65,
      emissive: baseColor,
      emissiveIntensity: isAttacked ? 0.6 : 0.25
    });

    const darkMaterial = new THREE.MeshStandardMaterial({
      color: 0x0f172a,
      roughness: 0.4,
      metalness: 0.8
    });

    const glowAccentMat = new THREE.MeshBasicMaterial({
      color: baseColor
    });

    const dType = (node.device_type || "unknown").toLowerCase();

    // ── 1. INTERNET / WAN UPLINK ──
    if (node.id === "internet" || dType === "internet") {
      const sphereGeo = new THREE.IcosahedronGeometry(1.6, 2);
      const cloudMesh = new THREE.Mesh(sphereGeo, mainMaterial);
      cloudMesh.name = "main";
      group.add(cloudMesh);

      const wireMat = new THREE.MeshBasicMaterial({ color: 0xc084fc, wireframe: true });
      const wireMesh = new THREE.Mesh(new THREE.IcosahedronGeometry(1.9, 1), wireMat);
      wireMesh.name = "spinner";
      group.add(wireMesh);
    }
    // ── 2. ROUTER / GATEWAY ROUTER ──
    else if (node.is_router || dType === "router") {
      const bodyGeo = new THREE.BoxGeometry(2.2, 0.45, 1.5);
      const bodyMesh = new THREE.Mesh(bodyGeo, mainMaterial);
      bodyMesh.name = "main";
      group.add(bodyMesh);

      // Dual Antennas
      const antGeo = new THREE.CylinderGeometry(0.05, 0.05, 1.4, 8);
      const antMat = new THREE.MeshStandardMaterial({ color: 0x1e293b, metalness: 0.9 });
      const ant1 = new THREE.Mesh(antGeo, antMat);
      ant1.position.set(-0.75, 0.7, -0.55);
      ant1.rotation.z = -0.15;
      group.add(ant1);

      const ant2 = new THREE.Mesh(antGeo, antMat);
      ant2.position.set(0.75, 0.7, -0.55);
      ant2.rotation.z = 0.15;
      group.add(ant2);

      // Front LED Status Bar
      const ledBar = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.06, 0.04), glowAccentMat);
      ledBar.position.set(0, 0, 0.76);
      group.add(ledBar);

      const ringGeo = new THREE.TorusGeometry(2.0, 0.04, 16, 32);
      const ringMat = new THREE.MeshBasicMaterial({ color: baseColor, wireframe: true });
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      ringMesh.name = "spinner";
      ringMesh.rotation.x = Math.PI / 2;
      group.add(ringMesh);
    }
    // ── 3. ACCESS POINT ──
    else if (dType === "access_point") {
      const saucerGeo = new THREE.CylinderGeometry(1.2, 0.8, 0.3, 24);
      const saucerMesh = new THREE.Mesh(saucerGeo, mainMaterial);
      saucerMesh.name = "main";
      group.add(saucerMesh);

      const ringLED = new THREE.Mesh(new THREE.TorusGeometry(0.5, 0.05, 16, 32), glowAccentMat);
      ringLED.rotation.x = Math.PI / 2;
      ringLED.position.y = 0.16;
      group.add(ringLED);
    }
    // ── 4. SWITCH ──
    else if (dType === "switch") {
      const swGeo = new THREE.BoxGeometry(2.5, 0.35, 1.2);
      const swMesh = new THREE.Mesh(swGeo, mainMaterial);
      swMesh.name = "main";
      group.add(swMesh);

      // RJ45 Port Array
      for (let i = 0; i < 8; i++) {
        const port = new THREE.Mesh(new THREE.BoxGeometry(0.18, 0.12, 0.04), glowAccentMat);
        port.position.set(-0.9 + i * 0.25, 0, 0.61);
        group.add(port);
      }
    }
    // ── 5. FIREWALL ──
    else if (dType === "firewall") {
      const fwGeo = new THREE.BoxGeometry(2.2, 0.6, 1.4);
      const fwMesh = new THREE.Mesh(fwGeo, mainMaterial);
      fwMesh.name = "main";
      group.add(fwMesh);

      const shieldBadge = new THREE.Mesh(new THREE.OctahedronGeometry(0.4, 0), new THREE.MeshBasicMaterial({ color: 0xef4444 }));
      shieldBadge.position.set(0, 0.4, 0.3);
      group.add(shieldBadge);
    }
    // ── 6. LAPTOP ──
    else if (dType === "laptop") {
      // Keyboard Base Slab
      const baseGeo = new THREE.BoxGeometry(1.6, 0.1, 1.1);
      const baseMesh = new THREE.Mesh(baseGeo, mainMaterial);
      baseMesh.name = "main";
      group.add(baseMesh);

      // Open Display Screen
      const screenGeo = new THREE.BoxGeometry(1.55, 1.0, 0.06);
      const screenMesh = new THREE.Mesh(screenGeo, mainMaterial);
      screenMesh.position.set(0, 0.52, -0.5);
      screenMesh.rotation.x = -0.22;
      group.add(screenMesh);

      // Glowing Display Matrix Face
      const displayFace = new THREE.Mesh(new THREE.PlaneGeometry(1.4, 0.85), new THREE.MeshBasicMaterial({ color: 0x0f172a }));
      displayFace.position.set(0, 0.52, -0.46);
      displayFace.rotation.x = -0.22;
      group.add(displayFace);
    }
    // ── 7. DESKTOP / WORKSTATION ──
    else if (dType === "desktop") {
      // Standalone Monitor Display
      const monScreen = new THREE.Mesh(new THREE.BoxGeometry(1.5, 0.95, 0.08), mainMaterial);
      monScreen.position.set(-0.35, 0.65, 0);
      monScreen.name = "main";
      group.add(monScreen);

      // Monitor Stand Post & Base
      const standPost = new THREE.Mesh(new THREE.CylinderGeometry(0.04, 0.04, 0.4, 8), darkMaterial);
      standPost.position.set(-0.35, 0.18, 0);
      group.add(standPost);

      const standBase = new THREE.Mesh(new THREE.BoxGeometry(0.6, 0.04, 0.5), darkMaterial);
      standBase.position.set(-0.35, 0.02, 0);
      group.add(standBase);

      // Mid-Tower CPU Case placed beside monitor
      const tower = new THREE.Mesh(new THREE.BoxGeometry(0.55, 1.3, 1.1), darkMaterial);
      tower.position.set(0.75, 0.65, 0);
      group.add(tower);

      const towerLED = new THREE.Mesh(new THREE.BoxGeometry(0.06, 0.8, 0.04), glowAccentMat);
      towerLED.position.set(0.75, 0.65, 0.56);
      group.add(towerLED);
    }
    // ── 8. MOBILE / SMARTPHONE ──
    else if (dType === "mobile") {
      // Slim Ergonomic Smartphone
      const phoneGeo = new THREE.BoxGeometry(0.72, 1.45, 0.07);
      const phoneMesh = new THREE.Mesh(phoneGeo, mainMaterial);
      phoneMesh.name = "main";
      phoneMesh.rotation.x = -0.25;
      group.add(phoneMesh);

      // Glossy OLED Screen
      const screenMat = new THREE.MeshBasicMaterial({ color: 0x020617 });
      const screenMesh = new THREE.Mesh(new THREE.PlaneGeometry(0.64, 1.32), screenMat);
      screenMesh.position.set(0, 0, 0.04);
      screenMesh.rotation.x = -0.25;
      group.add(screenMesh);

      // Camera Bump
      const camBump = new THREE.Mesh(new THREE.BoxGeometry(0.24, 0.32, 0.04), darkMaterial);
      camBump.position.set(0.18, 0.48, -0.05);
      camBump.rotation.x = -0.25;
      group.add(camBump);
    }
    // ── 9. TABLET ──
    else if (dType === "tablet") {
      const tabGeo = new THREE.BoxGeometry(1.25, 1.65, 0.07);
      const tabMesh = new THREE.Mesh(tabGeo, mainMaterial);
      tabMesh.name = "main";
      tabMesh.rotation.x = -0.25;
      group.add(tabMesh);

      const tabScreen = new THREE.Mesh(new THREE.PlaneGeometry(1.15, 1.5), new THREE.MeshBasicMaterial({ color: 0x020617 }));
      tabScreen.position.set(0, 0, 0.04);
      tabScreen.rotation.x = -0.25;
      group.add(tabScreen);
    }
    // ── 10. SERVER / MONITORING SERVER ──
    else if (node.is_monitoring_server || dType === "server") {
      const rackGeo = new THREE.BoxGeometry(1.4, 2.2, 1.4);
      const rackMesh = new THREE.Mesh(rackGeo, mainMaterial);
      rackMesh.name = "main";
      group.add(rackMesh);

      // Drive Bay LEDs
      for (let i = 0; i < 4; i++) {
        const led = new THREE.Mesh(new THREE.BoxGeometry(1.15, 0.1, 0.04), glowAccentMat);
        led.position.set(0, -0.65 + i * 0.42, 0.72);
        group.add(led);
      }
    }
    // ── 11. PRINTER ──
    else if (dType === "printer") {
      const pBody = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.8, 1.2), mainMaterial);
      pBody.name = "main";
      group.add(pBody);

      // Top paper feeder
      const feeder = new THREE.Mesh(new THREE.BoxGeometry(0.9, 0.4, 0.06), darkMaterial);
      feeder.position.set(0, 0.5, -0.4);
      feeder.rotation.x = -0.3;
      group.add(feeder);

      // Front paper tray
      const tray = new THREE.Mesh(new THREE.BoxGeometry(0.8, 0.04, 0.5), darkMaterial);
      tray.position.set(0, -0.15, 0.8);
      group.add(tray);
    }
    // ── 12. CAMERA / CCTV ──
    else if (dType === "camera") {
      const camBody = new THREE.Mesh(new THREE.CylinderGeometry(0.35, 0.35, 0.9, 16), mainMaterial);
      camBody.rotation.x = Math.PI / 3;
      camBody.name = "main";
      group.add(camBody);

      const lens = new THREE.Mesh(new THREE.CylinderGeometry(0.25, 0.25, 0.1, 16), new THREE.MeshBasicMaterial({ color: 0x000000 }));
      lens.position.set(0, -0.2, 0.4);
      lens.rotation.x = Math.PI / 3;
      group.add(lens);
    }
    // ── 13. IOT / SMART DEVICE / SENSOR ──
    else if (dType === "iot" || dType === "plc" || dType === "smart_meter") {
      const iotGeo = new THREE.BoxGeometry(0.9, 0.6, 0.7);
      const iotMesh = new THREE.Mesh(iotGeo, mainMaterial);
      iotMesh.name = "main";
      group.add(iotMesh);

      const stubAnt = new THREE.Mesh(new THREE.CylinderGeometry(0.03, 0.03, 0.6, 8), darkMaterial);
      stubAnt.position.set(0.3, 0.5, 0);
      group.add(stubAnt);

      const centerLED = new THREE.Mesh(new THREE.SphereGeometry(0.08, 8, 8), glowAccentMat);
      centerLED.position.set(0, 0.1, 0.36);
      group.add(centerLED);
    }
    // ── 14. NAS STORAGE ──
    else if (dType === "nas") {
      const nasGeo = new THREE.BoxGeometry(1.2, 1.2, 1.2);
      const nasMesh = new THREE.Mesh(nasGeo, mainMaterial);
      nasMesh.name = "main";
      group.add(nasMesh);

      // 4 Drive Caddies
      for (let i = 0; i < 4; i++) {
        const caddy = new THREE.Mesh(new THREE.BoxGeometry(0.18, 0.85, 0.04), darkMaterial);
        caddy.position.set(-0.38 + i * 0.25, 0, 0.61);
        group.add(caddy);
      }
    }
    // ── 15. UNKNOWN DEVICE (Default Fallback) ──
    else {
      // Geometric faceted mystery prism with glowing center
      const unkGeo = new THREE.OctahedronGeometry(0.9, 0);
      const unkMesh = new THREE.Mesh(unkGeo, mainMaterial);
      unkMesh.name = "main";
      group.add(unkMesh);

      const wireUnk = new THREE.Mesh(new THREE.OctahedronGeometry(1.1, 0), new THREE.MeshBasicMaterial({ color: baseColor, wireframe: true }));
      wireUnk.name = "spinner";
      group.add(wireUnk);
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
        const displayType = (p.node.device_type || "unknown").toUpperCase();
        const confLabel = typeof p.node.classification_confidence === "number"
          ? `${p.node.classification_confidence.toFixed(0)}%`
          : (p.node.classification_confidence || "Low");

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
              <span style={{ fontSize: 9, color: "var(--accent-cyan)", fontWeight: 600 }}>({confLabel})</span>
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
