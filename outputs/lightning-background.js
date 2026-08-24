(function initLoginLightningBackground() {
  const DEFAULT_OPTIONS = {
    hue: 158,
    xOffset: 0,
    speed: 0.75,
    intensity: 0.9,
    size: 0.9
  };

  class LightningBackground {
    constructor(canvas, options = {}) {
      this.canvas = canvas;
      this.options = { ...DEFAULT_OPTIONS, ...options };
      this.gl = null;
      this.program = null;
      this.uniforms = {};
      this.animationFrameId = 0;
      this.startTime = 0;
      this.running = false;
      this.resizeCanvas = this.resizeCanvas.bind(this);
      this.render = this.render.bind(this);
    }

    init() {
      if (this.gl) return true;
      const gl = this.canvas.getContext("webgl", {
        antialias: true,
        alpha: true,
        premultipliedAlpha: false
      });
      if (!gl) return false;
      this.gl = gl;

      const vertexShaderSource = `
        attribute vec2 aPosition;
        void main() {
          gl_Position = vec4(aPosition, 0.0, 1.0);
        }
      `;

      const fragmentShaderSource = `
        precision mediump float;
        uniform vec2 iResolution;
        uniform float iTime;
        uniform float uHue;
        uniform float uXOffset;
        uniform float uSpeed;
        uniform float uIntensity;
        uniform float uSize;

        #define OCTAVE_COUNT 10

        vec3 hsv2rgb(vec3 c) {
          vec3 rgb = clamp(abs(mod(c.x * 6.0 + vec3(0.0, 4.0, 2.0), 6.0) - 3.0) - 1.0, 0.0, 1.0);
          return c.z * mix(vec3(1.0), rgb, c.y);
        }

        float hash11(float p) {
          p = fract(p * .1031);
          p *= p + 33.33;
          p *= p + p;
          return fract(p);
        }

        float hash12(vec2 p) {
          vec3 p3 = fract(vec3(p.xyx) * .1031);
          p3 += dot(p3, p3.yzx + 33.33);
          return fract((p3.x + p3.y) * p3.z);
        }

        mat2 rotate2d(float theta) {
          float c = cos(theta);
          float s = sin(theta);
          return mat2(c, -s, s, c);
        }

        float noise(vec2 p) {
          vec2 ip = floor(p);
          vec2 fp = fract(p);
          float a = hash12(ip);
          float b = hash12(ip + vec2(1.0, 0.0));
          float c = hash12(ip + vec2(0.0, 1.0));
          float d = hash12(ip + vec2(1.0, 1.0));
          vec2 t = smoothstep(0.0, 1.0, fp);
          return mix(mix(a, b, t.x), mix(c, d, t.x), t.y);
        }

        float fbm(vec2 p) {
          float value = 0.0;
          float amplitude = 0.5;
          for (int i = 0; i < OCTAVE_COUNT; ++i) {
            value += amplitude * noise(p);
            p *= rotate2d(0.45);
            p *= 2.0;
            amplitude *= 0.5;
          }
          return value;
        }

        void main() {
          vec2 uv = gl_FragCoord.xy / iResolution.xy;
          uv = 2.0 * uv - 1.0;
          uv.x *= iResolution.x / iResolution.y;
          uv.x += uXOffset;

          float time = iTime * uSpeed;
          uv += 2.0 * fbm(uv * uSize + 0.8 * time) - 1.0;

          float dist = abs(uv.x);
          vec3 baseColor = hsv2rgb(vec3(uHue / 360.0, 0.78, 0.92));
          float flicker = mix(0.015, 0.08, hash11(time));
          vec3 col = baseColor * (flicker / max(dist, 0.001)) * uIntensity;
          col = pow(col, vec3(1.12));
          col *= 1.0 - smoothstep(0.05, 1.35, dist);

          float alpha = clamp(max(max(col.r, col.g), col.b) * 0.34, 0.0, 0.72);
          gl_FragColor = vec4(col, alpha);
        }
      `;

      const vertexShader = this.compileShader(vertexShaderSource, gl.VERTEX_SHADER);
      const fragmentShader = this.compileShader(fragmentShaderSource, gl.FRAGMENT_SHADER);
      if (!vertexShader || !fragmentShader) return false;

      const program = gl.createProgram();
      if (!program) return false;
      gl.attachShader(program, vertexShader);
      gl.attachShader(program, fragmentShader);
      gl.linkProgram(program);
      if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
        gl.deleteProgram(program);
        return false;
      }
      this.program = program;
      gl.useProgram(program);

      const vertices = new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]);
      const vertexBuffer = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, vertexBuffer);
      gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);

      const aPosition = gl.getAttribLocation(program, "aPosition");
      gl.enableVertexAttribArray(aPosition);
      gl.vertexAttribPointer(aPosition, 2, gl.FLOAT, false, 0, 0);

      this.uniforms = {
        iResolution: gl.getUniformLocation(program, "iResolution"),
        iTime: gl.getUniformLocation(program, "iTime"),
        uHue: gl.getUniformLocation(program, "uHue"),
        uXOffset: gl.getUniformLocation(program, "uXOffset"),
        uSpeed: gl.getUniformLocation(program, "uSpeed"),
        uIntensity: gl.getUniformLocation(program, "uIntensity"),
        uSize: gl.getUniformLocation(program, "uSize")
      };

      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE);
      gl.clearColor(0, 0, 0, 0);
      this.resizeCanvas();
      window.addEventListener("resize", this.resizeCanvas, { passive: true });
      return true;
    }

    compileShader(source, type) {
      const gl = this.gl;
      const shader = gl.createShader(type);
      if (!shader) return null;
      gl.shaderSource(shader, source);
      gl.compileShader(shader);
      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        gl.deleteShader(shader);
        return null;
      }
      return shader;
    }

    resizeCanvas() {
      const gl = this.gl;
      if (!gl) return;
      const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
      const displayWidth = Math.max(1, Math.floor(this.canvas.clientWidth * ratio));
      const displayHeight = Math.max(1, Math.floor(this.canvas.clientHeight * ratio));
      if (this.canvas.width !== displayWidth || this.canvas.height !== displayHeight) {
        this.canvas.width = displayWidth;
        this.canvas.height = displayHeight;
        gl.viewport(0, 0, this.canvas.width, this.canvas.height);
      }
    }

    start() {
      if (this.running) return;
      if (!this.init()) return;
      this.running = true;
      this.startTime = performance.now();
      this.animationFrameId = requestAnimationFrame(this.render);
    }

    stop() {
      this.running = false;
      if (this.animationFrameId) {
        cancelAnimationFrame(this.animationFrameId);
        this.animationFrameId = 0;
      }
      if (this.gl) {
        this.gl.clear(this.gl.COLOR_BUFFER_BIT);
      }
    }

    render() {
      if (!this.running || document.body.classList.contains("is-logged-in") || document.visibilityState === "hidden") {
        this.stop();
        return;
      }
      const gl = this.gl;
      const { hue, xOffset, speed, intensity, size } = this.options;
      this.resizeCanvas();
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.useProgram(this.program);
      gl.uniform2f(this.uniforms.iResolution, this.canvas.width, this.canvas.height);
      gl.uniform1f(this.uniforms.iTime, (performance.now() - this.startTime) / 1000);
      gl.uniform1f(this.uniforms.uHue, hue);
      gl.uniform1f(this.uniforms.uXOffset, xOffset);
      gl.uniform1f(this.uniforms.uSpeed, speed);
      gl.uniform1f(this.uniforms.uIntensity, intensity);
      gl.uniform1f(this.uniforms.uSize, size);
      gl.drawArrays(gl.TRIANGLES, 0, 6);
      this.animationFrameId = requestAnimationFrame(this.render);
    }
  }

  function boot() {
    const canvas = document.getElementById("loginLightningCanvas");
    const layer = document.querySelector(".login-lightning-webgl");
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!canvas || !layer || reduceMotion) return;
    const lightning = new LightningBackground(canvas);

    const sync = () => {
      const loginVisible = !document.body.classList.contains("is-logged-in");
      layer.classList.toggle("is-active", loginVisible);
      if (loginVisible && document.visibilityState === "visible") lightning.start();
      else lightning.stop();
    };

    new MutationObserver(sync).observe(document.body, { attributes: true, attributeFilter: ["class"] });
    document.addEventListener("visibilitychange", sync);
    sync();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
