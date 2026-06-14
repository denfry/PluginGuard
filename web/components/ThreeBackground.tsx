"use client";

import { useEffect, useRef } from "react";
import * as THREE from "three";

/**
 * Fixed, full-viewport WebGL backdrop: a slowly drifting particle field with a wireframe
 * "shield" icosahedron, in the brand phosphor-green. It sits behind all content (z-index below
 * the CSS blueprint grid) and reacts subtly to the pointer for parallax depth.
 *
 * Cheap by design — one points cloud + a couple of wireframes, capped pixel ratio, and a single
 * rotating group. Honors prefers-reduced-motion (renders one static frame, no animation loop) and
 * fully disposes its GPU resources on unmount.
 */
export function ThreeBackground() {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const prefersReduced =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

    const GREEN = new THREE.Color("#a3e635");
    const TEAL = new THREE.Color("#38bdf8");

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x0a0d0b, 0.055);

    const camera = new THREE.PerspectiveCamera(
      62,
      mount.clientWidth / mount.clientHeight,
      0.1,
      100,
    );
    camera.position.set(0, 0, 13);

    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
      powerPreference: "high-performance",
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(mount.clientWidth, mount.clientHeight);
    renderer.setClearColor(0x000000, 0);
    mount.appendChild(renderer.domElement);

    const group = new THREE.Group();
    scene.add(group);

    // ── Particle field ───────────────────────────────────────────────────
    const COUNT = 850;
    const positions = new Float32Array(COUNT * 3);
    const colors = new Float32Array(COUNT * 3);
    const tmp = new THREE.Color();
    for (let i = 0; i < COUNT; i++) {
      // Distribute in a soft spherical shell so the centre stays readable behind text.
      const r = 5 + Math.cbrt(Math.random()) * 9;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      positions[i * 3 + 2] = r * Math.cos(phi);
      tmp.copy(Math.random() > 0.82 ? TEAL : GREEN).multiplyScalar(0.55 + Math.random() * 0.45);
      colors[i * 3] = tmp.r;
      colors[i * 3 + 1] = tmp.g;
      colors[i * 3 + 2] = tmp.b;
    }
    const pGeo = new THREE.BufferGeometry();
    pGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    pGeo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    const pMat = new THREE.PointsMaterial({
      size: 0.07,
      vertexColors: true,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      sizeAttenuation: true,
    });
    const points = new THREE.Points(pGeo, pMat);
    group.add(points);

    // ── Wireframe "shield" core ──────────────────────────────────────────
    const shieldGeo = new THREE.IcosahedronGeometry(3.4, 1);
    const shieldMat = new THREE.MeshBasicMaterial({
      color: GREEN,
      wireframe: true,
      transparent: true,
      opacity: 0.14,
    });
    const shield = new THREE.Mesh(shieldGeo, shieldMat);
    group.add(shield);

    const innerGeo = new THREE.IcosahedronGeometry(2.1, 0);
    const innerMat = new THREE.MeshBasicMaterial({
      color: TEAL,
      wireframe: true,
      transparent: true,
      opacity: 0.1,
    });
    const inner = new THREE.Mesh(innerGeo, innerMat);
    group.add(inner);

    // ── Pointer parallax ─────────────────────────────────────────────────
    const target = { x: 0, y: 0 };
    const current = { x: 0, y: 0 };
    function onPointerMove(e: PointerEvent) {
      target.x = (e.clientX / window.innerWidth - 0.5) * 2;
      target.y = (e.clientY / window.innerHeight - 0.5) * 2;
    }
    if (!prefersReduced) {
      window.addEventListener("pointermove", onPointerMove, { passive: true });
    }

    function onResize() {
      if (!mount) return;
      const w = mount.clientWidth;
      const h = mount.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    }
    window.addEventListener("resize", onResize);

    let raf = 0;
    const clock = new THREE.Clock();

    function render() {
      const t = clock.getElapsedTime();
      group.rotation.y = t * 0.04;
      group.rotation.x = Math.sin(t * 0.12) * 0.12;
      shield.rotation.y = -t * 0.08;
      shield.rotation.x = t * 0.05;
      inner.rotation.y = t * 0.16;
      inner.rotation.z = t * 0.06;

      // Ease the camera toward the pointer for gentle parallax.
      current.x += (target.x - current.x) * 0.04;
      current.y += (target.y - current.y) * 0.04;
      camera.position.x = current.x * 1.6;
      camera.position.y = -current.y * 1.1;
      camera.lookAt(0, 0, 0);

      renderer.render(scene, camera);
    }

    if (prefersReduced) {
      render();
    } else {
      const loop = () => {
        render();
        raf = requestAnimationFrame(loop);
      };
      raf = requestAnimationFrame(loop);
    }

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("pointermove", onPointerMove);
      pGeo.dispose();
      pMat.dispose();
      shieldGeo.dispose();
      shieldMat.dispose();
      innerGeo.dispose();
      innerMat.dispose();
      renderer.dispose();
      if (renderer.domElement.parentNode === mount) {
        mount.removeChild(renderer.domElement);
      }
    };
  }, []);

  return (
    <div
      ref={mountRef}
      aria-hidden
      className="three-bg pointer-events-none fixed inset-0 -z-[2]"
    />
  );
}
