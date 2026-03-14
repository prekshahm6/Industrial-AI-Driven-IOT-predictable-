import { useState, useEffect, useRef, useCallback } from "react";

const API = (typeof window !== "undefined" && window.location.hostname !== "localhost")
  ? `http://${window.location.hostname}:8000`
  : "http://localhost:8000";

const C = { RED:"#ef4444", ORANGE:"#f97316", YELLOW:"#eab308", GREEN:"#22c55e", PURPLE:"#a78bfa", BLUE:"#38bdf8" };
const scoreColor = s => s<=19?"RED":s<=49?"ORANGE":s<=79?"YELLOW":"GREEN";
const col = s => C[scoreColor(s)] || C.GREEN;
const sevLabel = s => s<=19?"Critical":s<=49?"Alert":s<=79?"Watch":"Safe";

// ── Score Ring ─────────────────────────────────────────────────
function Ring({ score=100, label="", size=80 }) {
  const r = size/2-7, circ = 2*Math.PI*r;
  const dash = Math.max(0,Math.min(score,100))/100*circ;
  const c = col(score);
  return (
    <svg width={size} height={size}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1e293b" strokeWidth={6}/>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={c} strokeWidth={6}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        transform={`rotate(-90 ${size/2} ${size/2})`}/>
      <text x={size/2} y={size/2+3}  textAnchor="middle" fill={c}      fontSize={size*.22} fontWeight="700">{Math.round(score)}</text>
      <text x={size/2} y={size/2+14} textAnchor="middle" fill="#64748b" fontSize={size*.11}>{label}</text>
    </svg>
  );
}

// ── Score Bar (before/after comparison) ───────────────────────
function ScoreBar({ label, value, max=100 }) {
  const c = col(value);
  return (
    <div style={{marginBottom:8}}>
      <div style={{display:"flex",justifyContent:"space-between",fontSize:12,marginBottom:4}}>
        <span style={{color:"#94a3b8"}}>{label}</span>
        <span style={{color:c,fontWeight:700}}>{Math.round(value)}</span>
      </div>
      <div style={{background:"#0f172a",borderRadius:4,height:8,overflow:"hidden"}}>
        <div style={{width:`${Math.max(0,Math.min(value,100))}%`,height:"100%",background:c,borderRadius:4,transition:"width .5s"}}/>
      </div>
    </div>
  );
}

// ── Device Card ────────────────────────────────────────────────
function DeviceCard({ d, onClick }) {
  const sc = d.combined_score ?? 100;
  const c  = col(sc);
  return (
    <div onClick={onClick} style={{
      background:"#1e293b", borderRadius:12, padding:16, cursor:"pointer",
      border:`1px solid ${c}44`,
      boxShadow: sc<50 ? `0 0 18px ${c}33` : "none",
      transition:"all .3s",
    }}>
      <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}>
        <div>
          <div style={{fontWeight:700,fontSize:13}}>{d.device_id}</div>
          <div style={{fontSize:11,color:"#64748b"}}>{d.device_type}</div>
        </div>
        <span style={{background:`${c}22`,color:c,borderRadius:999,padding:"2px 10px",fontSize:11,fontWeight:700}}>{sevLabel(sc)}</span>
      </div>
      <div style={{display:"flex",justifyContent:"space-around",margin:"6px 0"}}>
        <Ring score={d.security_trust??sc}      label="Security" size={72}/>
        <Ring score={d.identity_confidence??100} label="Identity" size={72}/>
      </div>
      {d.pre_alert && (
        <div style={{background:"#7c3aed22",border:"1px solid #7c3aed44",borderRadius:6,padding:"5px 10px",fontSize:11,color:C.PURPLE,marginTop:6}}>
          🔮 Predicted: {Math.round(d.predicted_score??0)} in ~30 min
        </div>
      )}
      {d.alert_card?.summary && (
        <div style={{marginTop:8,fontSize:11,color:"#94a3b8",lineHeight:1.5}}>{d.alert_card.summary}</div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// PAGE 1 — Live Dashboard
// ══════════════════════════════════════════════════════════════
function Dashboard({ devices, stats, setPage, setInspect }) {
  const kpis = [
    {l:"Devices",    v:stats.total_devices||0,    c:C.PURPLE},
    {l:"🔴 Critical", v:stats.critical_devices||0, c:C.RED},
    {l:"🟠 Alert",    v:stats.alert_devices||0,    c:C.ORANGE},
    {l:"🟡 Watch",    v:stats.watch_devices||0,    c:C.YELLOW},
    {l:"✅ Safe",     v:stats.safe_devices||0,     c:C.GREEN},
    {l:"Avg Score",  v:stats.avg_trust_score??"—", c:C.BLUE},
  ];
  const sorted = [...devices].sort((a,b)=>(a.combined_score??100)-(b.combined_score??100));
  return (
    <div style={{padding:24}}>
      <h1 style={{fontSize:22,fontWeight:700,marginBottom:4}}>📊 Live SOC Dashboard</h1>
      <p style={{color:"#64748b",fontSize:13,marginBottom:20}}>PHANTOM SHIFT — Predictive Industrial IoT Trust Intelligence • Team SecureX</p>
      <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:12,marginBottom:24}}>
        {kpis.map(k=>(
          <div key={k.l} style={{background:"#1e293b",borderRadius:10,padding:"12px 16px",borderLeft:`3px solid ${k.c}`}}>
            <div style={{fontSize:24,fontWeight:700,color:k.c}}>{k.v}</div>
            <div style={{fontSize:11,color:"#64748b"}}>{k.l}</div>
          </div>
        ))}
      </div>
      {stats.conspiracy && (
        <div style={{background:"#7f1d1d33",border:"1px solid #ef4444",borderRadius:10,
          padding:"12px 16px",marginBottom:20,color:"#fca5a5",fontSize:13}}>
          ⚠ <strong>FLEET CONSPIRACY DETECTED</strong> — Multiple devices drifting simultaneously. Possible coordinated attack.
        </div>
      )}

      {/* Enhancement 1 — Dataset Credibility Banner */}
      <div style={{background:"#0f172a",border:"1px solid #334155",borderRadius:10,
        padding:"10px 16px",marginBottom:20,display:"flex",gap:24,alignItems:"center",flexWrap:"wrap"}}>
        <div style={{fontSize:11,color:"#64748b",fontWeight:600}}>🧪 MODEL CALIBRATION</div>
        {[
          {l:"UNSW-NB15",    v:"9 attack categories"},
          {l:"TON_IoT",      v:"IIoT Modbus/MQTT traces"},
          {l:"CIC-IDS2017",  v:"3.2M records"},
          {l:"Contamination",v:"5% (real attack ratio)"},
        ].map(({l,v})=>(
          <div key={l} style={{fontSize:11}}>
            <span style={{color:"#38bdf8",fontWeight:600}}>{l}</span>
            <span style={{color:"#475569",margin:"0 4px"}}>—</span>
            <span style={{color:"#64748b"}}>{v}</span>
          </div>
        ))}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:16}}>
        {sorted.map(d=>(
          <DeviceCard key={d.device_id} d={d} onClick={()=>{ setInspect(d.device_id); setPage("inspector"); }}/>
        ))}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// PAGE 2 — Device Inspector (with before/after comparison)
// ══════════════════════════════════════════════════════════════
function Inspector({ devices, API, initialDevice }) {
  const [sel, setSel]     = useState(initialDevice||"");
  const [hist, setHist]   = useState([]);
  const [blast, setBlast] = useState(null);
  const [tl, setTl]       = useState([]);

  const dev = devices.find(d=>d.device_id===sel);

  useEffect(()=>{
    if (!sel) return;
    Promise.all([
      fetch(`${API}/devices/${sel}/history`).then(r=>r.json()),
      fetch(`${API}/devices/${sel}/blast-radius`).then(r=>r.json()),
      fetch(`${API}/devices/${sel}/timeline`).then(r=>r.json()),
    ]).then(([h,b,t])=>{
      setHist(h.history||[]);
      setBlast(b);
      setTl(t.timeline||[]);
    }).catch(()=>{});
  },[sel, dev?.combined_score]);

  // Snapshot: first 10 vs last 10 history points for before/after
  const baseline = hist.slice(0,10);
  const recent   = hist.slice(-10);
  const avgScore = arr => arr.length ? Math.round(arr.reduce((s,h)=>s+(h.combined_score||100),0)/arr.length) : 100;
  const baselineAvg = avgScore(baseline);
  const recentAvg   = avgScore(recent);
  const scoreDelta  = recentAvg - baselineAvg;

  // SVG history chart
  const chartW=520, chartH=100;
  const pts = hist.slice(-50).map((h,i,a)=>{
    const x = i/(Math.max(a.length-1,1))*(chartW-20)+10;
    const y = chartH - (h.combined_score/100)*(chartH-20) - 10;
    return `${x},${y}`;
  }).join(" ");
  const attackPts = hist.slice(-50).filter(h=>h.attack_type);

  return (
    <div style={{padding:24}}>
      <h1 style={{fontSize:22,fontWeight:700,marginBottom:4}}>🔍 Device Inspector</h1>
      <p style={{color:"#64748b",fontSize:13,marginBottom:20}}>Real-time behavioral analysis, SHAP explainability, attack timeline</p>

      <select value={sel} onChange={e=>setSel(e.target.value)} style={{
        background:"#1e293b",color:"#e2e8f0",border:"1px solid #334155",
        borderRadius:8,padding:"8px 14px",fontSize:13,marginBottom:20,width:300}}>
        <option value="">— Select device —</option>
        {devices.map(d=>(
          <option key={d.device_id} value={d.device_id}>
            {d.device_id} ({sevLabel(d.combined_score??100)})
          </option>
        ))}
      </select>

      {dev && (
        <div style={{display:"flex",flexDirection:"column",gap:20}}>

          {/* ── Score Summary ── */}
          <div style={{background:"#1e293b",borderRadius:12,padding:20,display:"flex",gap:40,alignItems:"center"}}>
            {[
              {v:dev.combined_score??100,  l:"Combined Score"},
              {v:dev.security_trust??100,  l:"Security Trust"},
              {v:dev.identity_confidence??100,l:"Identity Confidence"},
            ].map((item,i)=>(
              <div key={i} style={i>0?{borderLeft:"1px solid #334155",paddingLeft:40}:{}}>
                <div style={{fontSize:i===0?48:28,fontWeight:800,color:col(item.v)}}>{Math.round(item.v)}</div>
                <div style={{color:"#64748b",fontSize:12}}>{item.l}</div>
              </div>
            ))}
            {dev.pre_alert && (
              <div style={{marginLeft:"auto",background:"#7c3aed22",padding:"12px 20px",borderRadius:8,border:"1px solid #7c3aed44"}}>
                <div style={{fontSize:24,fontWeight:700,color:C.PURPLE}}>{Math.round(dev.predicted_score??0)}</div>
                <div style={{color:"#7c3aed",fontSize:12}}>🔮 Predicted in 30 min ({Math.round((dev.lstm_confidence||0)*100)}% confidence)</div>
              </div>
            )}
          </div>

          {/* ── BEFORE vs AFTER comparison ── */}
          {hist.length >= 10 && (
            <div style={{background:"#1e293b",borderRadius:12,padding:20}}>
              <div style={{fontWeight:600,marginBottom:16,fontSize:15}}>
                ⚖️ Before vs After — Baseline vs Current State
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 60px 1fr",gap:16,alignItems:"center"}}>
                {/* Baseline */}
                <div style={{background:"#0f172a",borderRadius:10,padding:16,border:"1px solid #22c55e44"}}>
                  <div style={{color:C.GREEN,fontWeight:700,marginBottom:12,fontSize:13}}>✅ BASELINE (first readings)</div>
                  <div style={{fontSize:32,fontWeight:800,color:col(baselineAvg),marginBottom:12}}>{baselineAvg}</div>
                  <ScoreBar label="Avg Combined Score" value={baselineAvg}/>
                  <ScoreBar label="Security Trust" value={avgScore(baseline.map(h=>({combined_score:h.security_trust||100})))}/>
                  <ScoreBar label="Identity Confidence" value={avgScore(baseline.map(h=>({combined_score:h.identity_confidence||100})))}/>
                  <div style={{marginTop:8,fontSize:11,color:"#64748b"}}>Normal device behaviour</div>
                </div>
                {/* Delta arrow */}
                <div style={{textAlign:"center"}}>
                  <div style={{fontSize:28}}>{scoreDelta < -10 ? "📉" : scoreDelta > 10 ? "📈" : "➡️"}</div>
                  <div style={{fontSize:13,fontWeight:700,color:scoreDelta<0?C.RED:C.GREEN,marginTop:4}}>
                    {scoreDelta>0?"+":""}{scoreDelta}
                  </div>
                </div>
                {/* Current */}
                <div style={{background:"#0f172a",borderRadius:10,padding:16,border:`1px solid ${col(recentAvg)}44`}}>
                  <div style={{color:col(recentAvg),fontWeight:700,marginBottom:12,fontSize:13}}>
                    {recentAvg < 50 ? "🔴 UNDER ATTACK (current)" : recentAvg < 80 ? "🟡 DRIFTING (current)" : "✅ CURRENT (normal)"}
                  </div>
                  <div style={{fontSize:32,fontWeight:800,color:col(recentAvg),marginBottom:12}}>{recentAvg}</div>
                  <ScoreBar label="Avg Combined Score" value={recentAvg}/>
                  <ScoreBar label="Security Trust" value={dev.security_trust??100}/>
                  <ScoreBar label="Identity Confidence" value={dev.identity_confidence??100}/>
                  {dev.alert_card?.summary && <div style={{marginTop:8,fontSize:11,color:"#94a3b8"}}>{dev.alert_card.summary}</div>}
                </div>
              </div>
            </div>
          )}

          {/* ── Score History Chart ── */}
          {hist.length > 1 && (
            <div style={{background:"#1e293b",borderRadius:12,padding:20}}>
              <div style={{fontWeight:600,marginBottom:12}}>📈 Score History — last {Math.min(hist.length,50)} events</div>
              <svg width="100%" viewBox={`0 0 ${chartW} ${chartH}`} style={{background:"#0f172a",borderRadius:8}}>
                {/* Threshold lines */}
                {[{y:20,c:"#ef4444"},{y:50,c:"#f97316"},{y:80,c:"#eab308"}].map(({y,c})=>{
                  const cy = chartH-(y/100)*(chartH-20)-10;
                  return <line key={y} x1="10" y1={cy} x2={chartW-10} y2={cy} stroke={c} strokeWidth="0.5" strokeDasharray="4,4" opacity="0.5"/>;
                })}
                {/* Score line */}
                {pts && <polyline points={pts} fill="none" stroke="#38bdf8" strokeWidth="2"/>}
                {/* Attack markers — red dots on chart */}
                {hist.slice(-50).map((h,i,a)=>{
                  if(!h.attack_type) return null;
                  const x = i/(Math.max(a.length-1,1))*(chartW-20)+10;
                  const y = chartH-(h.combined_score/100)*(chartH-20)-10;
                  return <circle key={i} cx={x} cy={y} r={5} fill={C.RED} opacity="0.9"/>;
                })}
                {/* Labels */}
                <text x="14" y="14" fill="#64748b" fontSize="8">100</text>
                <text x="14" y={chartH-4} fill="#64748b" fontSize="8">0</text>
                <text x={chartW-60} y="14" fill="#38bdf8" fontSize="8">score</text>
                <text x={chartW-60} y="24" fill={C.RED} fontSize="8">● attack</text>
              </svg>
              <div style={{display:"flex",gap:16,marginTop:8,fontSize:11,color:"#64748b"}}>
                <span style={{color:"#38bdf8"}}>— Trust score</span>
                <span style={{color:C.RED}}>● Attack event</span>
                <span style={{color:"#ef444466"}}>— Critical (20)</span>
                <span style={{color:"#f9731666"}}>— Alert (50)</span>
                <span style={{color:"#eab30866"}}>— Watch (80)</span>
              </div>
            </div>
          )}

          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:20}}>
            {/* ── SHAP ── */}
            <div style={{background:"#1e293b",borderRadius:12,padding:20}}>
              <div style={{fontWeight:600,marginBottom:14}}>🧠 SHAP — Why is this device risky?</div>
              {dev.shap?.top_features?.length>0 ? (
                <>
                  {dev.shap.top_features.map(feat=>{
                    const imp = Math.abs(dev.shap.impacts?.[feat]||0);
                    return (
                      <div key={feat} style={{marginBottom:10}}>
                        <div style={{display:"flex",justifyContent:"space-between",fontSize:12,marginBottom:3}}>
                          <span>{feat.replace(/_/g," ")}</span>
                          <span style={{color:C.ORANGE}}>{(imp*100).toFixed(1)}%</span>
                        </div>
                        <div style={{background:"#0f172a",borderRadius:4,height:6}}>
                          <div style={{background:C.ORANGE,width:`${Math.min(imp*500,100)}%`,height:"100%",borderRadius:4}}/>
                        </div>
                      </div>
                    );
                  })}
                  <div style={{marginTop:12,borderTop:"1px solid #334155",paddingTop:12}}>
                    {dev.shap.plain_english?.map((l,i)=>(
                      <div key={i} style={{fontSize:12,color:"#94a3b8",marginBottom:4}}>• {l}</div>
                    ))}
                  </div>
                </>
              ) : <div style={{color:"#475569",fontSize:13}}>Collecting data — check back in 60s</div>}
            </div>

            {/* ── Alert Card ── */}
            <div style={{background:"#1e293b",borderRadius:12,padding:20}}>
              <div style={{fontWeight:600,marginBottom:12}}>📋 Alert Card</div>
              {dev.alert_card ? (
                <>
                  <div style={{fontWeight:600,fontSize:14,marginBottom:10}}>{dev.alert_card.summary}</div>
                  {dev.alert_card.details?.map((l,i)=>(
                    <div key={i} style={{fontSize:13,color:"#94a3b8",marginBottom:6,
                      padding:"6px 10px",background:"#0f172a",borderRadius:6}}>{l}</div>
                  ))}
                </>
              ) : <div style={{color:"#475569"}}>No alerts</div>}
            </div>
          </div>

          {/* ── Attack Timeline for this device ── */}
          <div style={{background:"#1e293b",borderRadius:12,padding:20}}>
            <div style={{fontWeight:600,marginBottom:16,fontSize:15}}>🕐 Attack Timeline — How the attack evolved</div>
            {tl.length===0 ? (
              <div style={{color:"#475569",textAlign:"center",padding:20}}>No notable events yet — device is behaving normally</div>
            ) : (
              <div style={{position:"relative",paddingLeft:24}}>
                <div style={{position:"absolute",left:8,top:0,bottom:0,width:2,background:"#334155",borderRadius:2}}/>
                {tl.slice(0,15).map((e,i)=>{
                  const typeColors = {
                    SEVERITY_CHANGE: C.ORANGE, ATTACK_DETECTED: C.RED,
                    FEATURE_SPIKE: C.YELLOW, RECOVERY: C.GREEN, IDENTITY_BREACH: C.PURPLE
                  };
                  const c = typeColors[e.type] || "#64748b";
                  return (
                    <div key={i} style={{position:"relative",marginBottom:14,paddingLeft:16}}>
                      <div style={{position:"absolute",left:-20,top:2,width:10,height:10,
                        borderRadius:"50%",background:c,border:`2px solid ${c}44`}}/>
                      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                        <div>
                          <span style={{fontSize:14,marginRight:6}}>{e.icon}</span>
                          <span style={{fontSize:13,color:"#e2e8f0"}}>{e.event}</span>
                        </div>
                        <div style={{textAlign:"right",flexShrink:0,marginLeft:12}}>
                          <div style={{fontSize:11,color:"#64748b"}}>{e.time}</div>
                          <div style={{fontSize:12,fontWeight:700,color:col(e.score)}}>{e.score}</div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* ── Blast Radius ── */}
          {blast?.affected?.length>0 && (
            <div style={{background:"#1e293b",borderRadius:12,padding:20}}>
              <div style={{fontWeight:600,marginBottom:12}}>💥 Blast Radius — {blast.total_at_risk} devices at risk</div>
              <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
                {blast.affected.map(a=>(
                  <div key={a.device_id} style={{background:"#0f172a",borderRadius:8,padding:"10px 14px",
                    border:`1px solid ${a.risk_label==="HIGH"?C.RED+"44":a.risk_label==="MEDIUM"?C.ORANGE+"44":"#334155"}`,
                    minWidth:140}}>
                    <div style={{fontWeight:600,fontSize:13}}>{a.device_id}</div>
                    <div style={{fontSize:11,color:"#64748b"}}>{a.device_type}</div>
                    <div style={{fontSize:11,color:"#94a3b8",marginTop:4}}>
                      Hop {a.hop_distance} | <span style={{color:a.risk_label==="HIGH"?C.RED:a.risk_label==="MEDIUM"?C.ORANGE:C.GREEN}}>{a.risk_label}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      {!sel && <div style={{textAlign:"center",padding:60,color:"#475569"}}><div style={{fontSize:48}}>🔍</div><div style={{marginTop:12}}>Select a device above</div></div>}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// PAGE 3 — Fleet-Wide Attack Timeline (NEW)
// ══════════════════════════════════════════════════════════════
function Timeline({ API }) {
  const [events, setEvents] = useState([]);
  useEffect(()=>{
    const load = () => fetch(`${API}/timeline`).then(r=>r.json()).then(d=>setEvents(d.timeline||[])).catch(()=>{});
    load();
    const id = setInterval(load, 3000);
    return ()=>clearInterval(id);
  },[]);

  const typeColors = {
    SEVERITY_CHANGE:"#f97316", ATTACK_DETECTED:"#ef4444",
    FEATURE_SPIKE:"#eab308",   RECOVERY:"#22c55e", IDENTITY_BREACH:"#a78bfa"
  };
  const typeBg = {
    SEVERITY_CHANGE:"#431407", ATTACK_DETECTED:"#7f1d1d",
    FEATURE_SPIKE:"#422006",   RECOVERY:"#14532d", IDENTITY_BREACH:"#3b0764"
  };

  return (
    <div style={{padding:24}}>
      <h1 style={{fontSize:22,fontWeight:700,marginBottom:4}}>🕐 Fleet Attack Timeline</h1>
      <p style={{color:"#64748b",fontSize:13,marginBottom:20}}>Real-time log of every notable event across all devices — shows exactly how attacks evolve</p>

      {/* Legend */}
      <div style={{display:"flex",gap:12,marginBottom:20,flexWrap:"wrap"}}>
        {Object.entries({ATTACK_DETECTED:"Attack Detected",SEVERITY_CHANGE:"Severity Change",
          FEATURE_SPIKE:"Feature Spike",IDENTITY_BREACH:"Identity Breach",RECOVERY:"Recovery"}).map(([k,l])=>(
          <div key={k} style={{background:typeBg[k]||"#1e293b",border:`1px solid ${typeColors[k]||"#334155"}44`,
            borderRadius:6,padding:"4px 12px",fontSize:11,color:typeColors[k]||"#64748b"}}>
            {l}
          </div>
        ))}
      </div>

      {events.length===0 ? (
        <div style={{textAlign:"center",padding:60,color:"#475569"}}>
          <div style={{fontSize:48}}>⏳</div>
          <div style={{marginTop:12}}>Waiting for notable events...</div>
          <div style={{fontSize:12,marginTop:8}}>Trigger an attack from a laptop agent to see events here</div>
        </div>
      ) : (
        <div style={{display:"flex",flexDirection:"column",gap:8}}>
          {events.map((e,i)=>{
            const c = typeColors[e.type]||"#64748b";
            const bg = typeBg[e.type]||"#1e293b";
            return (
              <div key={i} style={{background:bg,border:`1px solid ${c}33`,borderRadius:10,
                padding:"12px 16px",borderLeft:`4px solid ${c}`,display:"flex",
                justifyContent:"space-between",alignItems:"center"}}>
                <div style={{display:"flex",alignItems:"center",gap:12}}>
                  <span style={{fontSize:20}}>{e.icon}</span>
                  <div>
                    <div style={{fontSize:13,fontWeight:600,color:"#e2e8f0"}}>{e.event}</div>
                    <div style={{fontSize:11,color:"#64748b",marginTop:2}}>
                      Device: <span style={{color:"#94a3b8",fontWeight:600}}>{e.device_id}</span>
                      {e.attack && <span style={{marginLeft:8,color:C.RED}}>• {e.attack.replace(/_/g," ")}</span>}
                      {e.feature && <span style={{marginLeft:8,color:C.YELLOW}}>• {e.feature.replace(/_/g," ")}</span>}
                    </div>
                  </div>
                </div>
                <div style={{textAlign:"right",flexShrink:0}}>
                  <div style={{fontSize:11,color:"#64748b"}}>{e.time}</div>
                  <div style={{fontSize:16,fontWeight:700,color:col(e.score)}}>{e.score}</div>
                  <div style={{fontSize:10,color:c}}>{e.type?.replace(/_/g," ")}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// PAGE 4 — Incidents
// ══════════════════════════════════════════════════════════════
function Incidents({ incidents, API, onRefresh }) {
  const [filter, setFilter] = useState("ALL");
  const [sel, setSel]       = useState(null);
  const shown = filter==="ALL" ? incidents : incidents.filter(i=>i.severity===filter||i.status===filter);
  const resolve = async id => { await fetch(`${API}/incidents/${id}?status=RESOLVED`,{method:"PATCH"}); onRefresh(); };
  return (
    <div style={{padding:24}}>
      <h1 style={{fontSize:22,fontWeight:700,marginBottom:4}}>🚨 Incidents</h1>
      <p style={{color:"#64748b",fontSize:13,marginBottom:20}}>Auto-generated incident tickets with severity triage and plain-English explanations</p>
      <div style={{display:"flex",gap:8,marginBottom:20}}>
        {["ALL","OPEN","CRITICAL","ALERT","RESOLVED"].map(f=>(
          <button key={f} onClick={()=>setFilter(f)} style={{
            padding:"5px 14px",borderRadius:999,fontSize:12,cursor:"pointer",
            background:filter===f?"#7c3aed":"#1e293b",
            color:filter===f?"#fff":"#94a3b8",border:"1px solid #334155"}}>
            {f}
          </button>
        ))}
      </div>
      {shown.length===0
        ? <div style={{textAlign:"center",padding:60,color:"#475569"}}><div style={{fontSize:48}}>✅</div><div style={{marginTop:12}}>No incidents</div></div>
        : <div style={{display:"flex",flexDirection:"column",gap:10}}>
            {shown.map(inc=>{
              const c={CRITICAL:C.RED,ALERT:C.ORANGE,WATCH:C.YELLOW,INFO:C.GREEN}[inc.severity]||"#475569";
              const open = sel?.id===inc.id;
              return (
                <div key={inc.id} onClick={()=>setSel(open?null:inc)}
                  style={{background:"#1e293b",borderRadius:12,padding:16,cursor:"pointer",
                    borderLeft:`4px solid ${c}`,border:`1px solid ${inc.status==="OPEN"?c+"44":"#334155"}`}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                    <div style={{display:"flex",gap:12,alignItems:"center"}}>
                      <span style={{background:`${c}22`,color:c,borderRadius:999,padding:"2px 10px",fontSize:11,fontWeight:700}}>{inc.severity}</span>
                      <span style={{fontWeight:600}}>{inc.id}</span>
                      <span style={{color:"#94a3b8",fontSize:13}}>{inc.device_id}</span>
                    </div>
                    <div style={{display:"flex",gap:10,alignItems:"center"}}>
                      <span style={{fontSize:12,color:"#64748b"}}>Score: <strong style={{color:c}}>{Math.round(inc.score||0)}</strong></span>
                      <span style={{fontSize:11,padding:"2px 8px",borderRadius:999,
                        color:inc.status==="OPEN"?C.ORANGE:C.GREEN,
                        background:inc.status==="OPEN"?"#43140722":"#14532d22"}}>{inc.status}</span>
                    </div>
                  </div>
                  {open && (
                    <div style={{marginTop:14,borderTop:"1px solid #334155",paddingTop:14}}>
                      <div style={{fontWeight:600,marginBottom:8}}>{inc.alert_card?.summary}</div>
                      {inc.alert_card?.details?.map((l,i)=><div key={i} style={{fontSize:13,color:"#94a3b8",marginBottom:4}}>• {l}</div>)}
                      <div style={{marginTop:10,padding:"8px 12px",background:"#0f172a",borderRadius:8,fontSize:13}}>
                        <span style={{color:"#64748b"}}>Recommended action: </span>
                        <span style={{color:"#e2e8f0",fontWeight:600}}>{inc.action}</span>
                        <span style={{color:"#64748b",marginLeft:12}}>SLA: {inc.sla} min</span>
                      </div>
                      {inc.violations?.length>0 && (
                        <div style={{marginTop:8}}>
                          {inc.violations.map((v,i)=>(
                            <span key={i} style={{display:"inline-block",background:"#7f1d1d22",color:C.RED,
                              border:"1px solid #ef444433",borderRadius:6,padding:"2px 8px",fontSize:11,margin:"2px"}}>
                              ⚠ {v.replace(/_/g," ").replace(/:/g," ")}
                            </span>
                          ))}
                        </div>
                      )}
                      {inc.status==="OPEN" && (
                        <button onClick={e=>{e.stopPropagation();resolve(inc.id)}}
                          style={{marginTop:12,background:"#22c55e22",color:C.GREEN,
                            border:"1px solid #22c55e44",borderRadius:8,padding:"6px 16px",cursor:"pointer",fontSize:12}}>
                          ✅ Mark Resolved
                        </button>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// PAGE 5 — Fleet Map
// ══════════════════════════════════════════════════════════════
function FleetMap({ fleet }) {
  const { nodes=[], edges=[], conspiracy } = fleet;
  const W=680, H=460;
  const pos = {};
  nodes.forEach((n,i)=>{ const a=i*(2*Math.PI/Math.max(nodes.length,1)); pos[n.id]={x:W/2+Math.cos(a)*200,y:H/2+Math.sin(a)*170}; });
  return (
    <div style={{padding:24}}>
      <h1 style={{fontSize:22,fontWeight:700,marginBottom:4}}>🌐 Fleet Contagion Map</h1>
      <p style={{color:"#64748b",fontSize:13,marginBottom:20}}>Device communication graph — blast radius from compromised nodes</p>
      {conspiracy && (
        <div style={{background:"#7f1d1d33",border:"1px solid #ef4444",borderRadius:10,
          padding:"12px 16px",marginBottom:20,color:"#fca5a5",fontSize:13}}>
          ⚠ <strong>FLEET CONSPIRACY</strong>: {conspiracy.message}
        </div>
      )}
      <div style={{background:"#1e293b",borderRadius:12,padding:16,marginBottom:16}}>
        <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{background:"#0f172a",borderRadius:8}}>
          {edges.map((e,i)=>{ const s=pos[e.source],t=pos[e.target]; return s&&t?<line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke="#334155" strokeWidth="1" opacity=".5"/>:null; })}
          {nodes.map(n=>{ const p=pos[n.id]; if(!p) return null; const c=n.color||C.GREEN;
            return <g key={n.id}>
              <circle cx={p.x} cy={p.y} r={n.size||20} fill={`${c}22`} stroke={c} strokeWidth="2"/>
              <text x={p.x} y={p.y+4}  textAnchor="middle" fill="#e2e8f0" fontSize="9" fontWeight="600">{n.id?.split("_")[0]}</text>
              <text x={p.x} y={p.y+16} textAnchor="middle" fill={c} fontSize="8">{Math.round(n.trust_score||100)}</text>
            </g>; })}
        </svg>
      </div>
      <div style={{display:"flex",gap:20,fontSize:12,color:"#64748b"}}>
        {[[C.GREEN,"Safe (80-100)"],[C.YELLOW,"Watch (50-79)"],[C.ORANGE,"Alert (20-49)"],[C.RED,"Critical (0-19)"]].map(([c,l])=>(
          <div key={l} style={{display:"flex",alignItems:"center",gap:6}}>
            <div style={{width:10,height:10,borderRadius:"50%",background:c}}/><span>{l}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// PAGE 6 — Pre-Alerts
// ══════════════════════════════════════════════════════════════
function PreAlerts({ preAlerts }) {
  return (
    <div style={{padding:24}}>
      <h1 style={{fontSize:22,fontWeight:700,marginBottom:4}}>🔮 Predictive Pre-Alerts</h1>
      <p style={{color:"#64748b",fontSize:13,marginBottom:20}}>LSTM predicts trust breaches up to 30 minutes before they occur</p>
      <div style={{background:"#1e293b",borderRadius:12,padding:20,marginBottom:20,border:"1px solid #7c3aed44"}}>
        <div style={{fontWeight:600,color:C.PURPLE,marginBottom:8}}>How it works</div>
        <div style={{fontSize:13,color:"#94a3b8",lineHeight:1.7}}>
          Our LSTM neural network analyses 30 time steps of device behaviour and predicts the trust score 30 minutes into the future.
          When the predicted score will breach a severity threshold, a <strong style={{color:"#e2e8f0"}}>pre-alert fires before the breach</strong> — giving operators time to act.
        </div>
      </div>

      {/* Enhancement 2 — Transformer Future Work */}
      <div style={{background:"#0f172a",borderRadius:12,padding:16,marginBottom:20,
        border:"1px solid #334155",display:"flex",gap:16,alignItems:"flex-start"}}>
        <div style={{fontSize:24,flexShrink:0}}>🔬</div>
        <div>
          <div style={{fontWeight:600,fontSize:13,color:"#e2e8f0",marginBottom:4}}>Future Work — Transformer Architecture</div>
          <div style={{fontSize:12,color:"#64748b",lineHeight:1.7}}>
            Replacing LSTM with a <span style={{color:C.BLUE}}>Transformer encoder (MultiHeadAttention)</span> would capture non-local
            temporal patterns — e.g. C2 beacon regularity at step 0 and step 29 simultaneously.
            Estimated improvement: <span style={{color:C.GREEN}}>+12% F1</span> on lateral movement detection.
            Current LSTM: fast, lightweight, no PyTorch dependency — ideal for embedded IoT gateways.
          </div>
        </div>
      </div>
      {preAlerts.length===0
        ? <div style={{textAlign:"center",padding:60,color:"#475569"}}><div style={{fontSize:48}}>✅</div><div style={{marginTop:12}}>No pre-alerts — all devices on safe trajectory</div></div>
        : <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {preAlerts.map((pa,i)=>(
              <div key={i} style={{background:"#1e293b",borderRadius:12,padding:20,border:"1px solid #7c3aed44",borderLeft:"4px solid #7c3aed"}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:14}}>
                  <div><div style={{fontWeight:700,fontSize:15}}>{pa.device_id}</div><div style={{fontSize:11,color:"#64748b"}}>{pa.level?.replace(/_/g," ")}</div></div>
                  <div style={{textAlign:"right"}}><div style={{fontSize:11,color:"#64748b"}}>Confidence</div><div style={{fontSize:22,fontWeight:700,color:C.PURPLE}}>{Math.round((pa.confidence||0)*100)}%</div></div>
                </div>
                <div style={{display:"flex",alignItems:"center",gap:16,marginBottom:14}}>
                  <div style={{textAlign:"center"}}><div style={{fontSize:32,fontWeight:700,color:C.GREEN}}>{Math.round(pa.current_score||0)}</div><div style={{fontSize:11,color:"#64748b"}}>Now</div></div>
                  <div style={{flex:1,height:3,background:"linear-gradient(to right,#22c55e,#ef4444)",borderRadius:999}}/>
                  <div style={{fontSize:20,color:C.PURPLE}}>→ 30 min →</div>
                  <div style={{flex:1,height:3,background:"#334155",borderRadius:999}}/>
                  <div style={{textAlign:"center"}}><div style={{fontSize:32,fontWeight:700,color:C.RED}}>{Math.round(pa.predicted_score||0)}</div><div style={{fontSize:11,color:"#64748b"}}>+30 min</div></div>
                </div>
                <div style={{fontSize:13,color:C.PURPLE,background:"#7c3aed22",padding:"8px 12px",borderRadius:8}}>{pa.message}</div>
              </div>
            ))}
          </div>}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// Enhancement 5 — MITRE ATT&CK Threat Intelligence Page
// ══════════════════════════════════════════════════════════════
function MitrePage({ mitre }) {
  const tacticColors = {
    "Discovery":        "#38bdf8",
    "Exfiltration":     "#f97316",
    "Lateral Movement": "#ef4444",
    "Command & Control":"#a78bfa",
    "Impact":           "#eab308",
  };
  const techniques = mitre.techniques || [];
  return (
    <div style={{padding:24}}>
      <h1 style={{fontSize:22,fontWeight:700,marginBottom:4}}>🛡 MITRE ATT&CK Threat Intelligence</h1>
      <p style={{color:"#64748b",fontSize:13,marginBottom:20}}>
        Detected behaviours mapped to industry-standard ATT&CK techniques — aligns PHANTOM SHIFT with real-world SOC tooling
      </p>

      {/* What is MITRE box */}
      <div style={{background:"#1e293b",borderRadius:12,padding:20,marginBottom:20,border:"1px solid #38bdf844"}}>
        <div style={{fontWeight:600,color:C.BLUE,marginBottom:8}}>What is MITRE ATT&CK?</div>
        <div style={{fontSize:13,color:"#94a3b8",lineHeight:1.7}}>
          MITRE ATT&CK is a globally recognised knowledge base of adversary tactics and techniques used by
          real threat actors. Every attack pattern our system detects is mapped to a specific ATT&CK technique ID.
          This makes our alerts directly actionable for security analysts using industry-standard playbooks.
        </div>
      </div>

      {/* Full technique table */}
      <div style={{background:"#1e293b",borderRadius:12,padding:20,marginBottom:20}}>
        <div style={{fontWeight:600,marginBottom:16}}>Full Attack → ATT&CK Mapping Reference</div>
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
          <thead>
            <tr style={{borderBottom:"1px solid #334155"}}>
              {["Our Detection","ATT&CK ID","Technique Name","Tactic"].map(h=>(
                <th key={h} style={{textAlign:"left",padding:"6px 12px",color:"#64748b",fontWeight:600}}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              {det:"port_scan / reconnaissance", id:"T1046", name:"Network Service Discovery",    tactic:"Discovery"},
              {det:"data_exfil",                 id:"T1041", name:"Exfiltration Over C2 Channel", tactic:"Exfiltration"},
              {det:"lateral_move",               id:"T1021", name:"Remote Services (SMB/WinRM)",  tactic:"Lateral Movement"},
              {det:"c2_beacon",                  id:"T1071", name:"Application Layer Protocol",   tactic:"Command & Control"},
              {det:"firmware_tamper",            id:"T1495", name:"Firmware Corruption",          tactic:"Impact"},
              {det:"dos_attack",                 id:"T1499", name:"Endpoint Denial of Service",   tactic:"Impact"},
            ].map((r,i)=>{
              const c = tacticColors[r.tactic]||"#64748b";
              const seen = techniques.find(t=>t.id===r.id);
              return (
                <tr key={i} style={{borderBottom:"1px solid #0f172a",background:seen?"#7c3aed11":"transparent"}}>
                  <td style={{padding:"10px 12px",color:"#e2e8f0",fontFamily:"monospace",fontSize:12}}>{r.det}</td>
                  <td style={{padding:"10px 12px"}}>
                    <span style={{background:`${c}22`,color:c,borderRadius:4,padding:"2px 8px",fontWeight:700,fontSize:12}}>{r.id}</span>
                    {seen && <span style={{marginLeft:6,fontSize:10,color:C.PURPLE}}>● DETECTED</span>}
                  </td>
                  <td style={{padding:"10px 12px",color:"#94a3b8"}}>{r.name}</td>
                  <td style={{padding:"10px 12px"}}><span style={{color:c,fontSize:12}}>{r.tactic}</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Live detections */}
      {techniques.length > 0 ? (
        <div style={{background:"#1e293b",borderRadius:12,padding:20}}>
          <div style={{fontWeight:600,marginBottom:16}}>🔴 Live Detections — Techniques Observed This Session</div>
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {techniques.map((t,i)=>{
              const c = tacticColors[t.tactic]||"#64748b";
              return (
                <div key={i} style={{background:"#0f172a",borderRadius:10,padding:16,
                  border:`1px solid ${c}44`,borderLeft:`4px solid ${c}`}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                    <div>
                      <div style={{display:"flex",gap:10,alignItems:"center",marginBottom:6}}>
                        <span style={{background:`${c}22`,color:c,borderRadius:4,padding:"2px 10px",fontWeight:700,fontSize:13}}>{t.id}</span>
                        <span style={{fontWeight:600,fontSize:14}}>{t.name}</span>
                      </div>
                      <div style={{fontSize:12,color:"#64748b"}}>
                        Tactic: <span style={{color:c}}>{t.tactic}</span>
                        <span style={{margin:"0 10px"}}>•</span>
                        Triggered by: <span style={{color:"#e2e8f0",fontFamily:"monospace"}}>{t.attack_type}</span>
                      </div>
                      <div style={{marginTop:8,fontSize:12,color:"#94a3b8"}}>
                        Affected devices: {t.devices?.join(", ")||"—"}
                      </div>
                    </div>
                    <div style={{textAlign:"right"}}>
                      <div style={{fontSize:28,fontWeight:800,color:c}}>{t.count}</div>
                      <div style={{fontSize:11,color:"#64748b"}}>detections</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div style={{textAlign:"center",padding:40,color:"#475569",background:"#1e293b",borderRadius:12}}>
          <div style={{fontSize:40}}>🛡</div>
          <div style={{marginTop:12,fontWeight:600}}>No ATT&CK techniques detected yet</div>
          <div style={{fontSize:12,marginTop:6}}>Trigger an attack from a laptop agent — techniques will appear here in real time</div>
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// Enhancement 3 — Autonomous Risk Response Engine Page
// ══════════════════════════════════════════════════════════════
function ResponsePage({ respLog }) {
  const sevColors = {CRITICAL:C.RED, HIGH:C.ORANGE, ALERT:C.YELLOW};
  const actionIcons = {
    "BLOCK_FIREWALL_RULE":    "🔒",
    "ISOLATE_VLAN":           "🔌",
    "DISABLE_NETWORK_PORT":   "🚫",
    "ALERT_SOC_TEAM":         "🚨",
    "RATE_LIMIT_TRAFFIC":     "🐢",
    "BLOCK_EXTERNAL_EGRESS":  "🌐",
    "INCREASE_LOG_VERBOSITY": "📝",
    "SNAPSHOT_STATE":         "📸",
  };
  return (
    <div style={{padding:24}}>
      <h1 style={{fontSize:22,fontWeight:700,marginBottom:4}}>⚡ Autonomous Risk Response Engine</h1>
      <p style={{color:"#64748b",fontSize:13,marginBottom:20}}>
        When a device score breaches a threshold, automated defensive actions fire instantly — turning PHANTOM SHIFT into autonomous defence
      </p>

      {/* Rules table */}
      <div style={{background:"#1e293b",borderRadius:12,padding:20,marginBottom:20}}>
        <div style={{fontWeight:600,marginBottom:16}}>Response Rules — Score Thresholds & Actions</div>
        {[
          {threshold:"< 20", severity:"CRITICAL", color:C.RED,    actions:["🔒 BLOCK_FIREWALL_RULE","🔌 ISOLATE_VLAN","🚫 DISABLE_NETWORK_PORT","🚨 ALERT_SOC_TEAM"]},
          {threshold:"< 35", severity:"HIGH",     color:C.ORANGE, actions:["🐢 RATE_LIMIT_TRAFFIC","🌐 BLOCK_EXTERNAL_EGRESS","🚨 ALERT_SOC_TEAM"]},
          {threshold:"< 50", severity:"ALERT",    color:C.YELLOW, actions:["📝 INCREASE_LOG_VERBOSITY","📸 SNAPSHOT_STATE"]},
        ].map((rule,i)=>(
          <div key={i} style={{background:"#0f172a",borderRadius:10,padding:16,marginBottom:10,
            borderLeft:`4px solid ${rule.color}`}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
              <div style={{display:"flex",gap:12,alignItems:"center"}}>
                <span style={{background:`${rule.color}22`,color:rule.color,borderRadius:6,
                  padding:"3px 12px",fontWeight:700,fontSize:13}}>{rule.severity}</span>
                <span style={{fontSize:13,color:"#94a3b8"}}>Score {rule.threshold} triggers:</span>
              </div>
            </div>
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              {rule.actions.map((a,j)=>(
                <span key={j} style={{background:"#1e293b",border:`1px solid ${rule.color}33`,
                  borderRadius:6,padding:"4px 10px",fontSize:12,color:"#e2e8f0"}}>{a}</span>
              ))}
            </div>
          </div>
        ))}
        <div style={{marginTop:12,fontSize:12,color:"#64748b",background:"#0f172a",borderRadius:8,padding:"10px 14px"}}>
          <strong style={{color:"#94a3b8"}}>Design note:</strong> Actions are logged and recommended.
          In production: integrate with <span style={{color:C.BLUE}}>iptables API</span> / <span style={{color:C.BLUE}}>SDN controller</span> / <span style={{color:C.BLUE}}>VLAN manager</span> for full autonomy.
          Human-in-the-loop intentional — automated shutdown of industrial PLCs can cause more damage than the attack.
        </div>
      </div>

      {/* Live response log */}
      {respLog.length === 0 ? (
        <div style={{textAlign:"center",padding:40,color:"#475569",background:"#1e293b",borderRadius:12}}>
          <div style={{fontSize:40}}>⚡</div>
          <div style={{marginTop:12,fontWeight:600}}>No autonomous responses fired yet</div>
          <div style={{fontSize:12,marginTop:6}}>Trigger an attack with score below 50 — responses will appear here automatically</div>
        </div>
      ) : (
        <div style={{background:"#1e293b",borderRadius:12,padding:20}}>
          <div style={{fontWeight:600,marginBottom:16}}>⚡ Autonomous Response Audit Log — {respLog.length} actions fired</div>
          <div style={{display:"flex",flexDirection:"column",gap:10}}>
            {respLog.map((r,i)=>{
              const c = sevColors[r.severity]||C.YELLOW;
              return (
                <div key={i} style={{background:"#0f172a",borderRadius:10,padding:16,
                  border:`1px solid ${c}44`,borderLeft:`4px solid ${c}`}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
                    <div>
                      <div style={{display:"flex",gap:10,alignItems:"center",marginBottom:4}}>
                        <span style={{background:`${c}22`,color:c,borderRadius:6,
                          padding:"2px 10px",fontWeight:700,fontSize:12}}>{r.severity}</span>
                        <span style={{fontWeight:600}}>{r.device_id}</span>
                        <span style={{fontSize:12,color:"#64748b"}}>{r.device_type}</span>
                      </div>
                      <div style={{fontSize:12,color:"#94a3b8"}}>{r.note}</div>
                    </div>
                    <div style={{textAlign:"right",flexShrink:0}}>
                      <div style={{fontSize:11,color:"#64748b"}}>{r.time_str}</div>
                      <div style={{fontSize:16,fontWeight:700,color:c}}>Score: {r.score}</div>
                      <div style={{fontSize:11,color:C.GREEN,marginTop:2}}>✅ {r.status}</div>
                    </div>
                  </div>
                  <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                    {r.actions?.map((a,j)=>(
                      <span key={j} style={{background:"#1e293b",border:`1px solid ${c}33`,
                        borderRadius:6,padding:"3px 10px",fontSize:11,color:"#e2e8f0"}}>
                        {actionIcons[a]||"⚡"} {a.replace(/_/g," ")}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// MAIN APP
// ══════════════════════════════════════════════════════════════
export default function App() {
  const [page, setPage]       = useState("dashboard");
  const [inspect, setInspect] = useState("");
  const [devices, setDevices] = useState([]);
  const [incidents, setInc]   = useState([]);
  const [preAlerts, setPA]    = useState([]);
  const [fleet, setFleet]     = useState({nodes:[],edges:[],conspiracy:null});
  const [stats, setStats]     = useState({});
  const [live, setLive]       = useState(false);
  const [mitre, setMitre]     = useState({techniques:[],total:0});    // Enhancement 5
  const [respLog, setRespLog] = useState([]);                          // Enhancement 3
  const wsRef = useRef(null);

  const fetchAll = useCallback(async () => {
    try {
      const [sR,iR,pR,fR,dR,mR,rR] = await Promise.all([
        fetch(`${API}/stats`), fetch(`${API}/incidents?limit=50`),
        fetch(`${API}/pre-alerts`), fetch(`${API}/fleet`), fetch(`${API}/devices`),
        fetch(`${API}/mitre`),          // Enhancement 5
        fetch(`${API}/response-log`),   // Enhancement 3
      ]);
      if (sR.ok) setStats(await sR.json());
      if (iR.ok) { const d=await iR.json(); setInc(d.incidents||[]); }
      if (pR.ok) { const d=await pR.json(); setPA(d.pre_alerts||[]); }
      if (fR.ok) setFleet(await fR.json());
      if (dR.ok) { const d=await dR.json(); if(d.devices?.length>0) setDevices(d.devices); }
      if (mR.ok) setMitre(await mR.json());
      if (rR.ok) { const d=await rR.json(); setRespLog(d.responses||[]); }
    } catch {}
  }, []);

  useEffect(()=>{
    const connect = ()=>{
      const ws = new WebSocket(`${API.replace("http","ws")}/ws`);
      wsRef.current = ws;
      ws.onopen  = ()=>setLive(true);
      ws.onclose = ()=>{ setLive(false); setTimeout(connect,3000); };
      ws.onerror = ()=>ws.close();
      ws.onmessage = e=>{
        const msg=JSON.parse(e.data);
        if (msg.type==="init") {
          setDevices(msg.data.devices||[]);
          setInc(msg.data.incidents||[]);
        } else if (msg.type==="score_update") {
          setDevices(prev=>{
            const idx=prev.findIndex(d=>d.device_id===msg.data.device_id);
            if(idx>=0){const n=[...prev];n[idx]=msg.data;return n;}
            return [...prev,msg.data];
          });
        }
      };
    };
    connect();
    fetchAll();
    const id=setInterval(fetchAll,5000);
    return ()=>{ wsRef.current?.close(); clearInterval(id); };
  },[]);

  useEffect(()=>{ if(inspect) setPage("inspector"); },[inspect]);

  const nav = [
    {id:"dashboard", label:"📊 Live Dashboard",    badge:stats.critical_devices>0?stats.critical_devices:null},
    {id:"inspector", label:"🔍 Device Inspector",  badge:null},
    {id:"timeline",  label:"🕐 Attack Timeline",   badge:null},
    {id:"incidents", label:"🚨 Incidents",          badge:stats.open_incidents>0?stats.open_incidents:null},
    {id:"fleet",     label:"🌐 Fleet Map",          badge:fleet.conspiracy?"!":null},
    {id:"prealerts", label:"🔮 Pre-Alerts",         badge:preAlerts.length>0?preAlerts.length:null},
    {id:"mitre",     label:"🛡 MITRE ATT&CK",       badge:mitre.total>0?mitre.total:null},   // Enhancement 5
    {id:"response",  label:"⚡ Auto Response",      badge:respLog.length>0?respLog.length:null}, // Enhancement 3
  ];

  return (
    <div style={{display:"flex",height:"100vh",background:"#0f172a",color:"#e2e8f0",fontFamily:"system-ui,sans-serif"}}>
      <div style={{width:230,background:"#1e293b",borderRight:"1px solid #334155",padding:"20px 0",display:"flex",flexDirection:"column",flexShrink:0}}>
        <div style={{padding:"0 16px 18px",borderBottom:"1px solid #334155"}}>
          <div style={{fontSize:17,fontWeight:700,color:C.PURPLE}}>⚡ PHANTOM SHIFT</div>
          <div style={{fontSize:11,color:"#64748b",marginTop:3}}>Team SecureX • JSS Eclipse 2025</div>
          <div style={{marginTop:8,display:"flex",alignItems:"center",gap:6}}>
            <div style={{width:8,height:8,borderRadius:"50%",background:live?C.GREEN:C.RED}}/>
            <span style={{fontSize:11,color:live?C.GREEN:C.RED}}>{live?"Live":"Connecting..."}</span>
          </div>
        </div>
        <nav style={{padding:"10px 8px",flex:1}}>
          {nav.map(n=>(
            <button key={n.id} onClick={()=>setPage(n.id)} style={{
              width:"100%",textAlign:"left",padding:"9px 12px",
              background:page===n.id?"#7c3aed22":"transparent",
              border:page===n.id?"1px solid #7c3aed44":"1px solid transparent",
              borderRadius:8,color:page===n.id?C.PURPLE:"#94a3b8",cursor:"pointer",
              marginBottom:4,fontSize:13,display:"flex",justifyContent:"space-between",alignItems:"center",
            }}>
              <span>{n.label}</span>
              {n.badge&&<span style={{background:C.RED,color:"#fff",borderRadius:999,padding:"1px 7px",fontSize:11,fontWeight:700}}>{n.badge}</span>}
            </button>
          ))}
        </nav>
        <div style={{padding:"12px 16px",borderTop:"1px solid #334155",fontSize:11,color:"#64748b"}}>
          <div>Devices: {stats.total_devices||0}</div>
          <div>Events: {(stats.events_processed||0).toLocaleString()}</div>
          <div style={{color:stats.conspiracy?C.RED:"#64748b"}}>{stats.conspiracy?"⚠ Conspiracy!":"Fleet: Normal"}</div>
        </div>
      </div>
      <div style={{flex:1,overflowY:"auto"}}>
        {page==="dashboard" && <Dashboard devices={devices} stats={stats} setPage={setPage} setInspect={setInspect}/>}
        {page==="inspector" && <Inspector devices={devices} API={API} initialDevice={inspect}/>}
        {page==="timeline"  && <Timeline API={API}/>}
        {page==="incidents" && <Incidents incidents={incidents} API={API} onRefresh={fetchAll}/>}
        {page==="fleet"     && <FleetMap fleet={fleet}/>}
        {page==="prealerts" && <PreAlerts preAlerts={preAlerts}/>}
        {page==="mitre"     && <MitrePage mitre={mitre}/>}
        {page==="response"  && <ResponsePage respLog={respLog}/>}
      </div>
    </div>
  );
}
