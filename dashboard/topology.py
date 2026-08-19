"""
Network Topology Component — Live animated SVG showing ECU connections.

Three ECU service boxes connected to a central Client/Head Unit box via
SOME/IP lines. Animated dots travel along the lines when traffic flows,
and boxes glow red when under attack.

Polls the detector API every 2 seconds for per-service stats.
"""


def get_topology_html(detector_url: str = "http://localhost:5001") -> str:
    """Return the HTML/SVG/JS for the animated network topology."""

    return f"""
    <div id="topology-container" style="
        background: linear-gradient(135deg, #0a0a1a 0%, #111128 50%, #0a0a1a 100%);
        border-radius: 16px;
        padding: 20px 10px 10px 10px;
        border: 1px solid #2a2a4a;
        position: relative;
        height: 380px;
        overflow: hidden;
        font-family: 'Inter', sans-serif;
    ">
        <svg id="topo-svg" width="100%" height="100%" viewBox="0 0 600 360"
             xmlns="http://www.w3.org/2000/svg">
            <defs>
                <!-- Glow filters -->
                <filter id="glow-green" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="3" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
                <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="5" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
                <filter id="glow-blue" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="4" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>

                <!-- Dot gradient -->
                <radialGradient id="dot-green">
                    <stop offset="0%" stop-color="#2ECC71" stop-opacity="1"/>
                    <stop offset="100%" stop-color="#2ECC71" stop-opacity="0"/>
                </radialGradient>
                <radialGradient id="dot-red">
                    <stop offset="0%" stop-color="#E74C3C" stop-opacity="1"/>
                    <stop offset="100%" stop-color="#E74C3C" stop-opacity="0"/>
                </radialGradient>
                <radialGradient id="dot-sd">
                    <stop offset="0%" stop-color="#96CEB4" stop-opacity="1"/>
                    <stop offset="100%" stop-color="#96CEB4" stop-opacity="0"/>
                </radialGradient>
            </defs>

            <!-- Title -->
            <text x="300" y="22" text-anchor="middle" fill="#8888aa" font-size="12"
                  font-weight="500" letter-spacing="2">SOME/IP NETWORK TOPOLOGY</text>

            <!-- Connection lines (ECU → Client) -->
            <line id="line-hvac" x1="105" y1="110" x2="400" y2="180"
                  stroke="#334" stroke-width="2" stroke-dasharray="5,5" opacity="0.5"/>
            <line id="line-media" x1="105" y1="200" x2="400" y2="180"
                  stroke="#334" stroke-width="2" stroke-dasharray="5,5" opacity="0.5"/>
            <line id="line-nav" x1="105" y1="290" x2="400" y2="180"
                  stroke="#334" stroke-width="2" stroke-dasharray="5,5" opacity="0.5"/>

            <!-- Line labels -->
            <text x="245" y="135" text-anchor="middle" fill="#556" font-size="9"
                  transform="rotate(-13, 245, 135)">SOME/IP</text>
            <text x="250" y="193" text-anchor="middle" fill="#556" font-size="9">SOME/IP</text>
            <text x="245" y="255" text-anchor="middle" fill="#556" font-size="9"
                  transform="rotate(13, 245, 255)">SOME/IP</text>

            <!-- HVAC ECU Box -->
            <rect id="box-hvac" x="15" y="78" width="180" height="64" rx="10"
                  fill="#111" stroke="#FF6B6B" stroke-width="1.5" opacity="0.9"/>
            <text x="55" y="105" fill="#FF6B6B" font-size="13" font-weight="600">🌡 HVAC</text>
            <text x="55" y="122" fill="#888" font-size="10">Climate Control ECU</text>
            <text id="stat-hvac" x="55" y="136" fill="#556" font-size="9">0 msg/s</text>
            <circle id="indicator-hvac" cx="30" cy="110" r="5" fill="#333"/>

            <!-- Media ECU Box -->
            <rect id="box-media" x="15" y="168" width="180" height="64" rx="10"
                  fill="#111" stroke="#4ECDC4" stroke-width="1.5" opacity="0.9"/>
            <text x="55" y="195" fill="#4ECDC4" font-size="13" font-weight="600">🎵 Media</text>
            <text x="55" y="212" fill="#888" font-size="10">Infotainment ECU</text>
            <text id="stat-media" x="55" y="226" fill="#556" font-size="9">0 msg/s</text>
            <circle id="indicator-media" cx="30" cy="200" r="5" fill="#333"/>

            <!-- Navigation ECU Box -->
            <rect id="box-nav" x="15" y="258" width="180" height="64" rx="10"
                  fill="#111" stroke="#45B7D1" stroke-width="1.5" opacity="0.9"/>
            <text x="55" y="285" fill="#45B7D1" font-size="13" font-weight="600">🗺 Navigation</text>
            <text x="55" y="302" fill="#888" font-size="10">GPS / Routing ECU</text>
            <text id="stat-nav" x="55" y="316" fill="#556" font-size="9">0 msg/s</text>
            <circle id="indicator-nav" cx="30" cy="290" r="5" fill="#333"/>

            <!-- Client / Head Unit Box -->
            <rect id="box-client" x="385" y="130" width="195" height="100" rx="12"
                  fill="#111" stroke="#3498DB" stroke-width="2" opacity="0.9"/>
            <text x="483" y="165" text-anchor="middle" fill="#3498DB" font-size="14" font-weight="700">🖥 Head Unit</text>
            <text x="483" y="183" text-anchor="middle" fill="#888" font-size="10">Client / Gateway</text>
            <text id="stat-client" x="483" y="200" text-anchor="middle" fill="#556" font-size="10">Idle</text>
            <text id="stat-score" x="483" y="218" text-anchor="middle" fill="#556" font-size="9">Score: 0.000</text>

            <!-- SD broadcast indicator -->
            <rect id="sd-indicator" x="385" y="245" width="195" height="30" rx="6"
                  fill="#111" stroke="#96CEB4" stroke-width="1" opacity="0"/>
            <text id="sd-text" x="483" y="264" text-anchor="middle" fill="#96CEB4"
                  font-size="10" opacity="0">📡 Service Discovery Broadcast</text>

            <!-- Animated dots (hidden initially) -->
            <circle id="dot-hvac-1" r="4" fill="#2ECC71" opacity="0" filter="url(#glow-green)"/>
            <circle id="dot-hvac-2" r="4" fill="#2ECC71" opacity="0" filter="url(#glow-green)"/>
            <circle id="dot-media-1" r="4" fill="#2ECC71" opacity="0" filter="url(#glow-green)"/>
            <circle id="dot-media-2" r="4" fill="#2ECC71" opacity="0" filter="url(#glow-green)"/>
            <circle id="dot-nav-1" r="4" fill="#2ECC71" opacity="0" filter="url(#glow-green)"/>
            <circle id="dot-nav-2" r="4" fill="#2ECC71" opacity="0" filter="url(#glow-green)"/>

            <!-- Attack warning badges -->
            <g id="attack-badge-hvac" opacity="0">
                <rect x="145" y="80" width="46" height="18" rx="9" fill="#E74C3C"/>
                <text x="168" y="93" text-anchor="middle" fill="white" font-size="9" font-weight="600">ATTACK</text>
            </g>
            <g id="attack-badge-media" opacity="0">
                <rect x="145" y="170" width="46" height="18" rx="9" fill="#E74C3C"/>
                <text x="168" y="183" text-anchor="middle" fill="white" font-size="9" font-weight="600">ATTACK</text>
            </g>
            <g id="attack-badge-nav" opacity="0">
                <rect x="145" y="260" width="46" height="18" rx="9" fill="#E74C3C"/>
                <text x="168" y="273" text-anchor="middle" fill="white" font-size="9" font-weight="600">ATTACK</text>
            </g>
        </svg>
    </div>

    <script>
    (function() {{
        const DETECTOR = "{detector_url}";
        const POLL_MS = 2000;

        // Line endpoints for dot animation
        const lines = {{
            hvac:  {{ x1: 105, y1: 110, x2: 400, y2: 180 }},
            media: {{ x1: 105, y1: 200, x2: 400, y2: 180 }},
            nav:   {{ x1: 105, y1: 290, x2: 400, y2: 180 }},
        }};

        // Active animation timers
        const animTimers = {{ hvac: [], media: [], nav: [] }};

        function lerp(a, b, t) {{ return a + (b - a) * t; }}

        function animateDot(dotId, line, color, duration) {{
            const dot = document.getElementById(dotId);
            if (!dot) return;
            dot.setAttribute('fill', color);
            dot.setAttribute('opacity', '0.9');
            const start = performance.now();
            function step(now) {{
                const t = Math.min((now - start) / duration, 1);
                dot.setAttribute('cx', lerp(line.x1, line.x2, t));
                dot.setAttribute('cy', lerp(line.y1, line.y2, t));
                dot.setAttribute('opacity', String(0.9 * (1 - t * 0.5)));
                if (t < 1) requestAnimationFrame(step);
                else dot.setAttribute('opacity', '0');
            }}
            requestAnimationFrame(step);
        }}

        function startTrafficAnimation(service, msgCount, isAttack) {{
            // Clear existing timers
            animTimers[service].forEach(t => clearTimeout(t));
            animTimers[service] = [];

            const line = lines[service];
            const color = isAttack ? '#E74C3C' : '#2ECC71';
            const filter = isAttack ? 'url(#glow-red)' : 'url(#glow-green)';
            const dotCount = Math.min(msgCount, 6);
            const interval = isAttack ? 200 : 600;

            for (let i = 0; i < dotCount; i++) {{
                const dotId = `dot-${{service}}-${{(i % 2) + 1}}`;
                const dot = document.getElementById(dotId);
                if (dot) {{
                    dot.setAttribute('filter', filter);
                }}
                const tid = setTimeout(() => {{
                    animateDot(dotId, line, color, isAttack ? 400 : 800);
                }}, i * interval);
                animTimers[service].push(tid);
            }}
        }}

        function updateLine(service, active, isAttack) {{
            const line = document.getElementById(`line-${{service}}`);
            if (!line) return;
            if (isAttack) {{
                line.setAttribute('stroke', '#E74C3C');
                line.setAttribute('stroke-width', '3');
                line.setAttribute('opacity', '0.9');
                line.setAttribute('stroke-dasharray', '');
            }} else if (active) {{
                const colors = {{ hvac: '#FF6B6B', media: '#4ECDC4', nav: '#45B7D1' }};
                line.setAttribute('stroke', colors[service] || '#3498DB');
                line.setAttribute('stroke-width', '2');
                line.setAttribute('opacity', '0.7');
                line.setAttribute('stroke-dasharray', '');
            }} else {{
                line.setAttribute('stroke', '#334');
                line.setAttribute('stroke-width', '2');
                line.setAttribute('opacity', '0.5');
                line.setAttribute('stroke-dasharray', '5,5');
            }}
        }}

        function updateBox(service, active, isAttack) {{
            const box = document.getElementById(`box-${{service}}`);
            const indicator = document.getElementById(`indicator-${{service}}`);
            const badge = document.getElementById(`attack-badge-${{service}}`);
            if (!box) return;

            if (isAttack) {{
                box.setAttribute('stroke', '#E74C3C');
                box.setAttribute('stroke-width', '2.5');
                box.setAttribute('filter', 'url(#glow-red)');
                if (indicator) indicator.setAttribute('fill', '#E74C3C');
                if (badge) badge.setAttribute('opacity', '1');
            }} else if (active) {{
                const colors = {{ hvac: '#FF6B6B', media: '#4ECDC4', nav: '#45B7D1' }};
                box.setAttribute('stroke', colors[service] || '#3498DB');
                box.setAttribute('stroke-width', '1.5');
                box.removeAttribute('filter');
                if (indicator) indicator.setAttribute('fill', '#2ECC71');
                if (badge) badge.setAttribute('opacity', '0');
            }} else {{
                box.setAttribute('stroke', '#333');
                box.setAttribute('stroke-width', '1');
                box.removeAttribute('filter');
                if (indicator) indicator.setAttribute('fill', '#333');
                if (badge) badge.setAttribute('opacity', '0');
            }}
        }}

        function updateSD(active) {{
            const rect = document.getElementById('sd-indicator');
            const text = document.getElementById('sd-text');
            if (rect) rect.setAttribute('opacity', active ? '0.8' : '0');
            if (text) text.setAttribute('opacity', active ? '1' : '0');
        }}

        async function poll() {{
            try {{
                const resp = await fetch(DETECTOR + '/status');
                if (!resp.ok) return;
                const data = await resp.json();

                const svcMap = {{
                    '0x1001': 'hvac',
                    '0x2001': 'media',
                    '0x3001': 'nav',
                }};

                const services = data.services || {{}};
                let totalMsgs = 0;
                let anyAttack = false;

                for (const [sid, name] of Object.entries(svcMap)) {{
                    const svc = services[sid] || {{}};
                    const active = svc.active || false;
                    const underAttack = svc.under_attack || false;
                    const msgCount = svc.msg_count || 0;

                    totalMsgs += msgCount;
                    if (underAttack) anyAttack = true;

                    updateBox(name, active, underAttack);
                    updateLine(name, active, underAttack);

                    const stat = document.getElementById(`stat-${{name}}`);
                    if (stat) {{
                        const rate = (msgCount / 2).toFixed(1);
                        stat.textContent = underAttack
                            ? `⚠ ${{msgCount}} msgs (${{rate}}/s) — ATTACK`
                            : active ? `${{msgCount}} msgs (${{rate}}/s)` : 'idle';
                        stat.setAttribute('fill', underAttack ? '#E74C3C' : active ? '#888' : '#556');
                    }}

                    if (active) {{
                        startTrafficAnimation(name, msgCount, underAttack);
                    }}
                }}

                // Client box
                const clientStat = document.getElementById('stat-client');
                const clientBox = document.getElementById('box-client');
                const scoreStat = document.getElementById('stat-score');

                if (clientStat) {{
                    if (data.is_alert) {{
                        clientStat.textContent = '🚨 ANOMALY DETECTED';
                        clientStat.setAttribute('fill', '#E74C3C');
                    }} else if (totalMsgs > 0) {{
                        clientStat.textContent = `Processing ${{totalMsgs}} msgs`;
                        clientStat.setAttribute('fill', '#2ECC71');
                    }} else {{
                        clientStat.textContent = 'Idle';
                        clientStat.setAttribute('fill', '#556');
                    }}
                }}
                if (clientBox) {{
                    if (data.is_alert) {{
                        clientBox.setAttribute('stroke', '#E74C3C');
                        clientBox.setAttribute('filter', 'url(#glow-red)');
                    }} else {{
                        clientBox.setAttribute('stroke', '#3498DB');
                        clientBox.removeAttribute('filter');
                    }}
                }}
                if (scoreStat) {{
                    const xgb = (data.latest_score || 0).toFixed(3);
                    const ifo = (data.latest_iforest_score || 0).toFixed(3);
                    scoreStat.textContent = `XGB: ${{xgb}} | IF: ${{ifo}}`;
                    scoreStat.setAttribute('fill', data.is_alert ? '#E74C3C' : '#888');
                }}

                // SD broadcast
                updateSD(data.sd_active || false);

            }} catch (e) {{
                // Detector not ready yet
            }}
        }}

        // Start polling
        poll();
        setInterval(poll, POLL_MS);
    }})();
    </script>
    """
