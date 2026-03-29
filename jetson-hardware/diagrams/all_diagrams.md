# Smart Bus System — Excalidraw Diagrams

Render each diagram below using `create_view`, then export each as PNG. Save them as:
1. `01_system_architecture.png`
2. `02_detection_flowchart.png`
3. `03_attack_timeline.png`
4. `04_ns3_to_python_mapping.png`

---

## Diagram 1: System Deployment Architecture

```json
[
  {"type":"cameraUpdate","width":1200,"height":900,"x":-50,"y":-30},
  {"type":"rectangle","id":"bg","x":-30,"y":-10,"width":1100,"height":850,"backgroundColor":"#dbe4ff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#4a9eed","strokeWidth":1,"opacity":25},
  {"type":"text","id":"title","x":230,"y":10,"text":"System Deployment Architecture","fontSize":28,"strokeColor":"#1e1e1e"},
  {"type":"text","id":"subtitle","x":320,"y":48,"text":"WiFi Network \u2014 192.168.3.0/24","fontSize":18,"strokeColor":"#757575"},
  {"type":"rectangle","id":"jetson_zone","x":20,"y":100,"width":300,"height":360,"backgroundColor":"#a5d8ff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#4a9eed","strokeWidth":2,"opacity":40},
  {"type":"text","id":"jetson_title","x":55,"y":110,"text":"Jetson Orin Nano","fontSize":22,"strokeColor":"#2563eb"},
  {"type":"text","id":"jetson_ip","x":70,"y":140,"text":"192.168.3.199 (wlp1p1s0)","fontSize":16,"strokeColor":"#555555"},
  {"type":"rectangle","id":"gps_send","x":50,"y":180,"width":240,"height":40,"backgroundColor":"#b2f2bb","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"GPS Telemetry Sender","fontSize":16}},
  {"type":"rectangle","id":"cctv_send","x":50,"y":230,"width":240,"height":40,"backgroundColor":"#b2f2bb","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"CCTV Stream Sender","fontSize":16}},
  {"type":"rectangle","id":"tick_send","x":50,"y":280,"width":240,"height":40,"backgroundColor":"#b2f2bb","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"Ticketing Sender","fontSize":16}},
  {"type":"rectangle","id":"ddos_det","x":50,"y":340,"width":240,"height":40,"backgroundColor":"#ffc9c9","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#ef4444","label":{"text":"DDoS Detector","fontSize":16}},
  {"type":"rectangle","id":"gps_det","x":50,"y":390,"width":240,"height":40,"backgroundColor":"#ffc9c9","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#ef4444","label":{"text":"GPS Spoof Detector","fontSize":16}},
  {"type":"rectangle","id":"server_zone","x":720,"y":100,"width":300,"height":360,"backgroundColor":"#b2f2bb","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","strokeWidth":2,"opacity":40},
  {"type":"text","id":"server_title","x":790,"y":110,"text":"Server PC","fontSize":22,"strokeColor":"#15803d"},
  {"type":"text","id":"server_ip","x":780,"y":140,"text":"192.168.3.198 (Windows)","fontSize":16,"strokeColor":"#555555"},
  {"type":"rectangle","id":"gps_rx","x":750,"y":180,"width":240,"height":40,"backgroundColor":"#c3fae8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"GPS Receiver :5000","fontSize":16}},
  {"type":"rectangle","id":"cctv_rx","x":750,"y":230,"width":240,"height":40,"backgroundColor":"#c3fae8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"CCTV Receiver :6000","fontSize":16}},
  {"type":"rectangle","id":"tick_rx","x":750,"y":280,"width":240,"height":40,"backgroundColor":"#c3fae8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"Ticketing Receiver :7000","fontSize":16}},
  {"type":"rectangle","id":"forensic_rx","x":750,"y":330,"width":240,"height":40,"backgroundColor":"#c3fae8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"Forensic Receiver :8000","fontSize":16}},
  {"type":"rectangle","id":"hb_rx","x":750,"y":380,"width":240,"height":40,"backgroundColor":"#c3fae8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"Heartbeat Echo :5001","fontSize":16}},
  {"type":"arrow","id":"a_gps","x":290,"y":200,"width":460,"height":0,"points":[[0,0],[460,0]],"strokeColor":"#22c55e","strokeWidth":2,"endArrowhead":"arrow","startBinding":{"elementId":"gps_send","fixedPoint":[1,0.5]},"endBinding":{"elementId":"gps_rx","fixedPoint":[0,0.5]},"label":{"text":"UDP :5000","fontSize":14}},
  {"type":"arrow","id":"a_cctv","x":290,"y":250,"width":460,"height":0,"points":[[0,0],[460,0]],"strokeColor":"#22c55e","strokeWidth":2,"endArrowhead":"arrow","startBinding":{"elementId":"cctv_send","fixedPoint":[1,0.5]},"endBinding":{"elementId":"cctv_rx","fixedPoint":[0,0.5]},"label":{"text":"UDP :6000","fontSize":14}},
  {"type":"arrow","id":"a_tick","x":290,"y":300,"width":460,"height":0,"points":[[0,0],[460,0]],"strokeColor":"#22c55e","strokeWidth":2,"endArrowhead":"arrow","startBinding":{"elementId":"tick_send","fixedPoint":[1,0.5]},"endBinding":{"elementId":"tick_rx","fixedPoint":[0,0.5]},"label":{"text":"TCP :7000","fontSize":14}},
  {"type":"arrow","id":"a_hb","x":290,"y":400,"width":460,"height":0,"points":[[0,0],[460,0]],"strokeColor":"#4a9eed","strokeWidth":2,"endArrowhead":"arrow","startArrowhead":"arrow","label":{"text":"UDP :5001 (Heartbeat)","fontSize":14}},
  {"type":"rectangle","id":"attacker_zone","x":370,"y":580,"width":300,"height":200,"backgroundColor":"#ffc9c9","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#ef4444","strokeWidth":2,"opacity":40},
  {"type":"text","id":"atk_title","x":415,"y":590,"text":"Attacker Laptop","fontSize":22,"strokeColor":"#dc2626"},
  {"type":"text","id":"atk_ip","x":430,"y":620,"text":"192.168.3.198","fontSize":16,"strokeColor":"#555555"},
  {"type":"rectangle","id":"ddos_atk","x":400,"y":660,"width":220,"height":40,"backgroundColor":"#ffc9c9","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#ef4444","label":{"text":"DDoS Flood (30 Mbps)","fontSize":16}},
  {"type":"rectangle","id":"gps_atk","x":400,"y":710,"width":220,"height":40,"backgroundColor":"#ffd8a8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#f59e0b","label":{"text":"GPS Spoof Injector","fontSize":16}},
  {"type":"arrow","id":"a_ddos","x":400,"y":680,"width":-230,"height":-320,"points":[[0,0],[-230,-320]],"strokeColor":"#ef4444","strokeWidth":2,"endArrowhead":"arrow","strokeStyle":"dashed","label":{"text":"UDP flood :5000","fontSize":14}},
  {"type":"arrow","id":"a_spoof","x":400,"y":730,"width":-290,"height":-370,"points":[[0,0],[-290,-370]],"strokeColor":"#f59e0b","strokeWidth":2,"endArrowhead":"arrow","strokeStyle":"dashed","label":{"text":"Fake GPS :5000","fontSize":14}},
  {"type":"rectangle","id":"forensic_box","x":50,"y":470,"width":160,"height":50,"backgroundColor":"#d0bfff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#8b5cf6","label":{"text":"Forensic Upload\n10 MB via TCP","fontSize":14}},
  {"type":"arrow","id":"a_forensic","x":210,"y":495,"width":540,"height":-150,"points":[[0,0],[540,-150]],"strokeColor":"#8b5cf6","strokeWidth":2,"endArrowhead":"arrow","label":{"text":"TCP :8000","fontSize":14}},
  {"type":"rectangle","id":"telegram_box","x":170,"y":540,"width":160,"height":50,"backgroundColor":"#eebefa","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#8b5cf6","label":{"text":"Telegram Alert","fontSize":16}},
  {"type":"arrow","id":"a_tele","x":250,"y":540,"width":0,"height":-70,"points":[[0,0],[0,-70]],"strokeColor":"#8b5cf6","strokeWidth":1,"endArrowhead":"arrow","strokeStyle":"dashed"},
  {"type":"cameraUpdate","width":1200,"height":900,"x":-50,"y":-30}
]
```

---

## Diagram 2: Detection Logic Flowchart

```json
[
  {"type":"cameraUpdate","width":1200,"height":900,"x":-50,"y":-30},
  {"type":"text","id":"title2","x":260,"y":10,"text":"Detection Logic Flowchart","fontSize":28,"strokeColor":"#1e1e1e"},
  {"type":"text","id":"sub2","x":350,"y":48,"text":"ANY-mode trigger (1-of-N)","fontSize":18,"strokeColor":"#757575"},
  {"type":"rectangle","id":"zone_ddos","x":20,"y":90,"width":480,"height":520,"backgroundColor":"#ffc9c9","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#ef4444","strokeWidth":1,"opacity":20},
  {"type":"text","id":"ddos_label","x":170,"y":100,"text":"DDoS Detection Path","fontSize":20,"strokeColor":"#dc2626"},
  {"type":"rectangle","id":"zone_gps","x":560,"y":90,"width":480,"height":520,"backgroundColor":"#ffd8a8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#f59e0b","strokeWidth":1,"opacity":20},
  {"type":"text","id":"gps_label","x":680,"y":100,"text":"GPS Spoof Detection Path","fontSize":20,"strokeColor":"#b45309"},
  {"type":"rectangle","id":"incoming","x":100,"y":150,"width":220,"height":50,"backgroundColor":"#a5d8ff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#4a9eed","label":{"text":"Incoming Traffic\n(every 10s window)","fontSize":16}},
  {"type":"rectangle","id":"gps_in","x":660,"y":150,"width":220,"height":50,"backgroundColor":"#a5d8ff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#4a9eed","label":{"text":"Incoming GPS Packet\n(per-packet check)","fontSize":16}},
  {"type":"arrow","id":"a1_2","x":210,"y":200,"width":0,"height":40,"points":[[0,0],[0,40]],"strokeColor":"#1e1e1e","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"arrow","id":"a1b_2","x":770,"y":200,"width":0,"height":40,"points":[[0,0],[0,40]],"strokeColor":"#1e1e1e","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"diamond","id":"d_rate","x":120,"y":250,"width":200,"height":80,"backgroundColor":"#fff3bf","fillStyle":"solid","strokeColor":"#f59e0b","label":{"text":"Rate > 15 Mbps?","fontSize":16}},
  {"type":"diamond","id":"d_loss","x":120,"y":370,"width":200,"height":80,"backgroundColor":"#fff3bf","fillStyle":"solid","strokeColor":"#f59e0b","label":{"text":"Loss > 5%?","fontSize":16}},
  {"type":"diamond","id":"d_rtt","x":120,"y":490,"width":200,"height":80,"backgroundColor":"#fff3bf","fillStyle":"solid","strokeColor":"#f59e0b","label":{"text":"RTT > 100 ms?","fontSize":16}},
  {"type":"arrow","id":"a_rate_no","x":220,"y":330,"width":0,"height":40,"points":[[0,0],[0,40]],"strokeColor":"#757575","strokeWidth":2,"endArrowhead":"arrow","label":{"text":"No","fontSize":14}},
  {"type":"arrow","id":"a_loss_no","x":220,"y":450,"width":0,"height":40,"points":[[0,0],[0,40]],"strokeColor":"#757575","strokeWidth":2,"endArrowhead":"arrow","label":{"text":"No","fontSize":14}},
  {"type":"text","id":"or1","x":358,"y":270,"text":"OR","fontSize":20,"strokeColor":"#ef4444"},
  {"type":"text","id":"or2","x":358,"y":390,"text":"OR","fontSize":20,"strokeColor":"#ef4444"},
  {"type":"text","id":"or3","x":358,"y":510,"text":"OR","fontSize":20,"strokeColor":"#ef4444"},
  {"type":"arrow","id":"a_rate_yes","x":320,"y":290,"width":80,"height":0,"points":[[0,0],[80,0]],"strokeColor":"#ef4444","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"arrow","id":"a_loss_yes","x":320,"y":410,"width":80,"height":0,"points":[[0,0],[80,0]],"strokeColor":"#ef4444","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"arrow","id":"a_rtt_yes","x":320,"y":530,"width":80,"height":0,"points":[[0,0],[80,0]],"strokeColor":"#ef4444","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"arrow","id":"a_or1","x":420,"y":290,"width":0,"height":110,"points":[[0,0],[0,110]],"strokeColor":"#ef4444","strokeWidth":2,"endArrowhead":null},
  {"type":"arrow","id":"a_or2","x":420,"y":410,"width":0,"height":-10,"points":[[0,0],[0,-10]],"strokeColor":"#ef4444","strokeWidth":2,"endArrowhead":null},
  {"type":"diamond","id":"d_speed","x":660,"y":250,"width":220,"height":70,"backgroundColor":"#fff3bf","fillStyle":"solid","strokeColor":"#f59e0b","label":{"text":"Speed > 22.2 m/s?","fontSize":16}},
  {"type":"diamond","id":"d_jump","x":660,"y":350,"width":220,"height":70,"backgroundColor":"#fff3bf","fillStyle":"solid","strokeColor":"#f59e0b","label":{"text":"Jump > 1000 m?","fontSize":16}},
  {"type":"diamond","id":"d_corr","x":660,"y":450,"width":220,"height":70,"backgroundColor":"#fff3bf","fillStyle":"solid","strokeColor":"#f59e0b","label":{"text":"Corridor > 1500 m?","fontSize":16}},
  {"type":"arrow","id":"a_sp_no","x":770,"y":320,"width":0,"height":30,"points":[[0,0],[0,30]],"strokeColor":"#757575","strokeWidth":2,"endArrowhead":"arrow","label":{"text":"No","fontSize":14}},
  {"type":"arrow","id":"a_jp_no","x":770,"y":420,"width":0,"height":30,"points":[[0,0],[0,30]],"strokeColor":"#757575","strokeWidth":2,"endArrowhead":"arrow","label":{"text":"No","fontSize":14}},
  {"type":"text","id":"or4","x":910,"y":265,"text":"OR","fontSize":20,"strokeColor":"#f59e0b"},
  {"type":"text","id":"or5","x":910,"y":365,"text":"OR","fontSize":20,"strokeColor":"#f59e0b"},
  {"type":"text","id":"or6","x":910,"y":465,"text":"OR","fontSize":20,"strokeColor":"#f59e0b"},
  {"type":"arrow","id":"a_sp_yes","x":880,"y":285,"width":60,"height":0,"points":[[0,0],[60,0]],"strokeColor":"#f59e0b","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"arrow","id":"a_jp_yes","x":880,"y":385,"width":60,"height":0,"points":[[0,0],[60,0]],"strokeColor":"#f59e0b","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"arrow","id":"a_cr_yes","x":880,"y":485,"width":60,"height":0,"points":[[0,0],[60,0]],"strokeColor":"#f59e0b","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"arrow","id":"a_or3","x":960,"y":285,"width":0,"height":100,"points":[[0,0],[0,100]],"strokeColor":"#f59e0b","strokeWidth":2,"endArrowhead":null},
  {"type":"arrow","id":"a_or4","x":960,"y":385,"width":0,"height":-5,"points":[[0,0],[0,-5]],"strokeColor":"#f59e0b","strokeWidth":2,"endArrowhead":null},
  {"type":"diamond","id":"d_streak","x":660,"y":550,"width":220,"height":70,"backgroundColor":"#d0bfff","fillStyle":"solid","strokeColor":"#8b5cf6","label":{"text":"3 in a row?","fontSize":18}},
  {"type":"arrow","id":"a_to_streak","x":770,"y":520,"width":0,"height":30,"points":[[0,0],[0,30]],"strokeColor":"#1e1e1e","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"rectangle","id":"ddos_alert","x":130,"y":680,"width":180,"height":60,"backgroundColor":"#ffc9c9","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#ef4444","strokeWidth":2,"label":{"text":"DDoS DETECTED","fontSize":18}},
  {"type":"arrow","id":"a_ddos_trig","x":420,"y":530,"width":-200,"height":150,"points":[[0,0],[-200,150]],"strokeColor":"#ef4444","strokeWidth":2,"endArrowhead":"arrow","label":{"text":"ANY = Yes","fontSize":14}},
  {"type":"rectangle","id":"gps_alert","x":680,"y":680,"width":200,"height":60,"backgroundColor":"#ffd8a8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#f59e0b","strokeWidth":2,"label":{"text":"GPS SPOOF DETECTED","fontSize":16}},
  {"type":"arrow","id":"a_gps_trig","x":770,"y":620,"width":0,"height":60,"points":[[0,0],[0,60]],"strokeColor":"#f59e0b","strokeWidth":2,"endArrowhead":"arrow","label":{"text":"Yes","fontSize":14}},
  {"type":"arrow","id":"a_to_response","x":310,"y":710,"width":370,"height":0,"points":[[0,0],[370,0]],"strokeColor":"#8b5cf6","strokeWidth":2,"endArrowhead":null,"strokeStyle":"dashed"},
  {"type":"rectangle","id":"response","x":380,"y":780,"width":280,"height":70,"backgroundColor":"#d0bfff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#8b5cf6","strokeWidth":2,"label":{"text":"Forensic Upload (10 MB)\n+ Telegram Alert","fontSize":18}},
  {"type":"arrow","id":"a_resp","x":520,"y":740,"width":0,"height":40,"points":[[0,0],[0,40]],"strokeColor":"#8b5cf6","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"cameraUpdate","width":1200,"height":900,"x":-50,"y":0}
]
```

---

## Diagram 3: Combined Attack Test Timeline

```json
[
  {"type":"cameraUpdate","width":1200,"height":900,"x":-50,"y":-30},
  {"type":"text","id":"title3","x":300,"y":10,"text":"Combined Attack Test Timeline","fontSize":28,"strokeColor":"#1e1e1e"},
  {"type":"text","id":"sub3","x":360,"y":48,"text":"GPS Spoof + DDoS Flood in Single Session","fontSize":18,"strokeColor":"#757575"},
  {"type":"arrow","id":"timeline","x":50,"y":420,"width":1000,"height":0,"points":[[0,0],[1000,0]],"strokeColor":"#1e1e1e","strokeWidth":3,"endArrowhead":"arrow"},
  {"type":"text","id":"time_label","x":470,"y":440,"text":"Time (seconds)","fontSize":16,"strokeColor":"#757575"},
  {"type":"arrow","id":"t0","x":80,"y":400,"width":0,"height":40,"points":[[0,0],[0,40]],"strokeColor":"#1e1e1e","strokeWidth":2,"endArrowhead":null},
  {"type":"text","id":"t0l","x":60,"y":450,"text":"t = 0","fontSize":16,"strokeColor":"#1e1e1e"},
  {"type":"arrow","id":"t90","x":230,"y":400,"width":0,"height":40,"points":[[0,0],[0,40]],"strokeColor":"#1e1e1e","strokeWidth":2,"endArrowhead":null},
  {"type":"text","id":"t90l","x":200,"y":450,"text":"t = 90s","fontSize":16,"strokeColor":"#1e1e1e"},
  {"type":"arrow","id":"t651","x":470,"y":400,"width":0,"height":40,"points":[[0,0],[0,40]],"strokeColor":"#1e1e1e","strokeWidth":2,"endArrowhead":null},
  {"type":"text","id":"t651l","x":440,"y":450,"text":"t = 651s","fontSize":16,"strokeColor":"#1e1e1e"},
  {"type":"arrow","id":"t675","x":680,"y":400,"width":0,"height":40,"points":[[0,0],[0,40]],"strokeColor":"#1e1e1e","strokeWidth":2,"endArrowhead":null},
  {"type":"text","id":"t675l","x":650,"y":450,"text":"t = 675s","fontSize":16,"strokeColor":"#1e1e1e"},
  {"type":"arrow","id":"t695","x":860,"y":400,"width":0,"height":40,"points":[[0,0],[0,40]],"strokeColor":"#1e1e1e","strokeWidth":2,"endArrowhead":null},
  {"type":"text","id":"t695l","x":830,"y":450,"text":"t = 695s","fontSize":16,"strokeColor":"#1e1e1e"},
  {"type":"rectangle","id":"warmup","x":80,"y":360,"width":150,"height":30,"backgroundColor":"#a5d8ff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#4a9eed","strokeWidth":1,"label":{"text":"Warmup (90s)","fontSize":14}},
  {"type":"rectangle","id":"baseline","x":230,"y":360,"width":240,"height":30,"backgroundColor":"#b2f2bb","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","strokeWidth":1,"label":{"text":"Baseline \u2014 IDLE","fontSize":14}},
  {"type":"rectangle","id":"gps_atk3","x":470,"y":360,"width":200,"height":30,"backgroundColor":"#ffd8a8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#f59e0b","strokeWidth":1,"label":{"text":"GPS Spoof (15 pkts)","fontSize":14}},
  {"type":"rectangle","id":"ddos_atk3","x":680,"y":360,"width":180,"height":30,"backgroundColor":"#ffc9c9","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#ef4444","strokeWidth":1,"label":{"text":"DDoS Flood","fontSize":14}},
  {"type":"rectangle","id":"sys_start","x":40,"y":100,"width":180,"height":60,"backgroundColor":"#a5d8ff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#4a9eed","label":{"text":"System Start\nmain.py launched","fontSize":16}},
  {"type":"arrow","id":"a_start","x":80,"y":160,"width":0,"height":200,"points":[[0,0],[0,200]],"strokeColor":"#4a9eed","strokeWidth":1,"endArrowhead":"arrow","strokeStyle":"dashed"},
  {"type":"rectangle","id":"warmup_done","x":180,"y":100,"width":180,"height":60,"backgroundColor":"#b2f2bb","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"Warmup Complete\nDetection Active","fontSize":16}},
  {"type":"arrow","id":"a_warm","x":230,"y":160,"width":0,"height":200,"points":[[0,0],[0,200]],"strokeColor":"#22c55e","strokeWidth":1,"endArrowhead":"arrow","strokeStyle":"dashed"},
  {"type":"rectangle","id":"gps_det3","x":440,"y":190,"width":200,"height":50,"backgroundColor":"#ffd8a8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#f59e0b","label":{"text":"GPS Spoof Detected\nt = 654s (~3s TTD)","fontSize":14}},
  {"type":"arrow","id":"a_gps_det3","x":510,"y":240,"width":0,"height":120,"points":[[0,0],[0,120]],"strokeColor":"#f59e0b","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"rectangle","id":"forensic3","x":440,"y":260,"width":200,"height":50,"backgroundColor":"#d0bfff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#8b5cf6","label":{"text":"Forensic Upload\n10 MB in 1.49s","fontSize":14}},
  {"type":"arrow","id":"a_forensic3","x":540,"y":310,"width":0,"height":50,"points":[[0,0],[0,50]],"strokeColor":"#8b5cf6","strokeWidth":1,"endArrowhead":"arrow","strokeStyle":"dashed"},
  {"type":"rectangle","id":"ddos_det3","x":660,"y":190,"width":200,"height":50,"backgroundColor":"#ffc9c9","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#ef4444","label":{"text":"DDoS Detected\nt = 681s (~6s TTD)","fontSize":14}},
  {"type":"arrow","id":"a_ddos_det3","x":730,"y":240,"width":0,"height":120,"points":[[0,0],[0,120]],"strokeColor":"#ef4444","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"rectangle","id":"resume","x":860,"y":360,"width":160,"height":30,"backgroundColor":"#b2f2bb","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","strokeWidth":1,"label":{"text":"Normal Resumes","fontSize":14}},
  {"type":"text","id":"legend_title","x":40,"y":510,"text":"Legend","fontSize":20,"strokeColor":"#1e1e1e"},
  {"type":"rectangle","id":"leg1","x":40,"y":540,"width":20,"height":20,"backgroundColor":"#a5d8ff","fillStyle":"solid","strokeColor":"#4a9eed"},
  {"type":"text","id":"leg1t","x":70,"y":542,"text":"Warmup","fontSize":16,"strokeColor":"#555555"},
  {"type":"rectangle","id":"leg2","x":170,"y":540,"width":20,"height":20,"backgroundColor":"#b2f2bb","fillStyle":"solid","strokeColor":"#22c55e"},
  {"type":"text","id":"leg2t","x":200,"y":542,"text":"Normal","fontSize":16,"strokeColor":"#555555"},
  {"type":"rectangle","id":"leg3","x":300,"y":540,"width":20,"height":20,"backgroundColor":"#ffd8a8","fillStyle":"solid","strokeColor":"#f59e0b"},
  {"type":"text","id":"leg3t","x":330,"y":542,"text":"GPS Spoof","fontSize":16,"strokeColor":"#555555"},
  {"type":"rectangle","id":"leg4","x":450,"y":540,"width":20,"height":20,"backgroundColor":"#ffc9c9","fillStyle":"solid","strokeColor":"#ef4444"},
  {"type":"text","id":"leg4t","x":480,"y":542,"text":"DDoS Flood","fontSize":16,"strokeColor":"#555555"},
  {"type":"rectangle","id":"leg5","x":600,"y":540,"width":20,"height":20,"backgroundColor":"#d0bfff","fillStyle":"solid","strokeColor":"#8b5cf6"},
  {"type":"text","id":"leg5t","x":630,"y":542,"text":"Forensic Response","fontSize":16,"strokeColor":"#555555"},
  {"type":"cameraUpdate","width":1200,"height":900,"x":-50,"y":-30}
]
```

---

## Diagram 4: ns-3 to Python Component Mapping

```json
[
  {"type":"cameraUpdate","width":1200,"height":900,"x":-50,"y":-30},
  {"type":"text","id":"title4","x":180,"y":10,"text":"ns-3 Simulation to Jetson Deployment Mapping","fontSize":26,"strokeColor":"#1e1e1e"},
  {"type":"text","id":"sub4","x":310,"y":46,"text":"C++ (smart-bus.cc) to Python (jetson/) translation","fontSize":18,"strokeColor":"#757575"},
  {"type":"rectangle","id":"ns3_zone","x":20,"y":90,"width":420,"height":720,"backgroundColor":"#dbe4ff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#4a9eed","strokeWidth":2,"opacity":30},
  {"type":"text","id":"ns3_title","x":100,"y":100,"text":"ns-3 Simulation (C++)","fontSize":22,"strokeColor":"#2563eb"},
  {"type":"text","id":"ns3_file","x":120,"y":128,"text":"smart-bus.cc (1790 lines)","fontSize":16,"strokeColor":"#555555"},
  {"type":"rectangle","id":"py_zone","x":560,"y":90,"width":480,"height":720,"backgroundColor":"#d3f9d8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","strokeWidth":2,"opacity":30},
  {"type":"text","id":"py_title","x":650,"y":100,"text":"Jetson Deployment (Python)","fontSize":22,"strokeColor":"#15803d"},
  {"type":"text","id":"py_file","x":680,"y":128,"text":"jetson/ (40 files, 4533 lines)","fontSize":16,"strokeColor":"#555555"},
  {"type":"rectangle","id":"ns_gps","x":50,"y":170,"width":360,"height":50,"backgroundColor":"#a5d8ff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#4a9eed","label":{"text":"GpsTelemetryApp (UDP :5000)\nSendPacket() \u2014 200B GPS1 format","fontSize":14}},
  {"type":"rectangle","id":"py_gps","x":590,"y":170,"width":420,"height":50,"backgroundColor":"#b2f2bb","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"traffic/gps_telemetry.py\nGpsTelemetrySender \u2014 1 pkt/s, 200B UDP","fontSize":14}},
  {"type":"arrow","id":"a_gps4","x":410,"y":195,"width":180,"height":0,"points":[[0,0],[180,0]],"strokeColor":"#4a9eed","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"rectangle","id":"ns_cctv","x":50,"y":240,"width":360,"height":50,"backgroundColor":"#a5d8ff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#4a9eed","label":{"text":"CctvStreamApp (UDP :6000)\nOnOffApplication 1 Mbps, 1400B","fontSize":14}},
  {"type":"rectangle","id":"py_cctv","x":590,"y":240,"width":420,"height":50,"backgroundColor":"#b2f2bb","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"traffic/cctv_stream.py\nCctvStreamSender \u2014 1 Mbps, 1400B UDP","fontSize":14}},
  {"type":"arrow","id":"a_cctv4","x":410,"y":265,"width":180,"height":0,"points":[[0,0],[180,0]],"strokeColor":"#4a9eed","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"rectangle","id":"ns_tick","x":50,"y":310,"width":360,"height":50,"backgroundColor":"#a5d8ff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#4a9eed","label":{"text":"TicketingApp (TCP :7000)\nOnOffApplication bursty 256B","fontSize":14}},
  {"type":"rectangle","id":"py_tick","x":590,"y":310,"width":420,"height":50,"backgroundColor":"#b2f2bb","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#22c55e","label":{"text":"traffic/ticketing.py\nTicketingSender \u2014 TCP bursts 256B","fontSize":14}},
  {"type":"arrow","id":"a_tick4","x":410,"y":335,"width":180,"height":0,"points":[[0,0],[180,0]],"strokeColor":"#4a9eed","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"rectangle","id":"ns_ddos","x":50,"y":400,"width":360,"height":50,"backgroundColor":"#ffc9c9","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#ef4444","label":{"text":"DDoS Detection Logic\nCheckDDoS() \u2014 rate/loss/delay","fontSize":14}},
  {"type":"rectangle","id":"py_ddos","x":590,"y":400,"width":420,"height":50,"backgroundColor":"#ffc9c9","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#ef4444","label":{"text":"detection/ddos_detector.py\nDDoSDetector \u2014 rate/loss/RTT via heartbeat","fontSize":14}},
  {"type":"arrow","id":"a_ddos4","x":410,"y":425,"width":180,"height":0,"points":[[0,0],[180,0]],"strokeColor":"#ef4444","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"rectangle","id":"ns_gps_d","x":50,"y":470,"width":360,"height":50,"backgroundColor":"#ffd8a8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#f59e0b","label":{"text":"GPS Spoof Detection Logic\nCheckGpsSpoof() \u2014 speed/jump/corridor","fontSize":14}},
  {"type":"rectangle","id":"py_gps_d","x":590,"y":470,"width":420,"height":50,"backgroundColor":"#ffd8a8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#f59e0b","label":{"text":"detection/gps_detector.py\nGpsDetector \u2014 speed/jump/corridor + streak","fontSize":14}},
  {"type":"arrow","id":"a_gps_d4","x":410,"y":495,"width":180,"height":0,"points":[[0,0],[180,0]],"strokeColor":"#f59e0b","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"rectangle","id":"ns_forensic","x":50,"y":540,"width":360,"height":50,"backgroundColor":"#d0bfff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#8b5cf6","label":{"text":"ForensicUpload()\n10,485,760 bytes via TCP :8000","fontSize":14}},
  {"type":"rectangle","id":"py_forensic","x":590,"y":540,"width":420,"height":50,"backgroundColor":"#d0bfff","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#8b5cf6","label":{"text":"forensic/evidence_upload.py\n10 MB TCP upload in 1448B chunks","fontSize":14}},
  {"type":"arrow","id":"a_forensic4","x":410,"y":565,"width":180,"height":0,"points":[[0,0],[180,0]],"strokeColor":"#8b5cf6","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"rectangle","id":"ns_flow","x":50,"y":620,"width":360,"height":50,"backgroundColor":"#c3fae8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#06b6d4","label":{"text":"FlowMonitor\nns-3 built-in loss/delay/throughput","fontSize":14}},
  {"type":"rectangle","id":"py_hb","x":590,"y":620,"width":420,"height":50,"backgroundColor":"#c3fae8","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#06b6d4","label":{"text":"detection/heartbeat.py\nUDP probe/echo for loss + RTT","fontSize":14}},
  {"type":"arrow","id":"a_flow4","x":410,"y":645,"width":180,"height":0,"points":[[0,0],[180,0]],"strokeColor":"#06b6d4","strokeWidth":2,"endArrowhead":"arrow","label":{"text":"replaced by","fontSize":14}},
  {"type":"rectangle","id":"ns_routes","x":50,"y":700,"width":360,"height":50,"backgroundColor":"#eebefa","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#8b5cf6","label":{"text":"CreateRoutes()\n10 Al-Ahsa bus routes, waypoints[]","fontSize":14}},
  {"type":"rectangle","id":"py_routes","x":590,"y":700,"width":420,"height":50,"backgroundColor":"#eebefa","fillStyle":"solid","roundness":{"type":3},"strokeColor":"#8b5cf6","label":{"text":"routes.py\nAL_AHSA_ROUTES \u2014 10 routes, same coords","fontSize":14}},
  {"type":"arrow","id":"a_routes4","x":410,"y":725,"width":180,"height":0,"points":[[0,0],[180,0]],"strokeColor":"#8b5cf6","strokeWidth":2,"endArrowhead":"arrow"},
  {"type":"text","id":"note4","x":460,"y":780,"text":"All thresholds, packet formats, and detection logic preserved exactly","fontSize":16,"strokeColor":"#555555"},
  {"type":"cameraUpdate","width":1200,"height":900,"x":-50,"y":-30}
]
```
