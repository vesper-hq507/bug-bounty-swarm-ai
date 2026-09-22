#!/usr/bin/env bash
# Scripted animation for the README: adaptive attack-path scoring.
# Recorded with VHS (docs/adaptive-scoring.tape). Palette matches banner/hero.svg.
set -u
AMBER=$'\e[38;2;245;166;35m'; GREEN=$'\e[38;2;61;220;151m'; PURPLE=$'\e[38;2;127;119;221m'
CYAN=$'\e[38;2;87;199;255m'; RED=$'\e[38;2;255;107;107m'; YELLOW=$'\e[38;2;255;192;77m'
MUTED=$'\e[38;2;92;101;119m'; WHITE=$'\e[38;2;230;233;239m'; B=$'\e[1m'; R=$'\e[0m'
p(){ printf '%b\n' "$1"; }; s(){ sleep "$1"; }
clear
p ""
p "  ${AMBER}${B}██████  ██     ██  █████  ██████  ███    ███${R}"
p "  ${AMBER}${B}     ██ ██  █  ██ ███████ ██████  ██ ████ ██${R}"
p "  ${AMBER}${B}███████  ███ ███  ██   ██ ██   ██ ██      ██${R}"
p ""
p "  ${GREEN}${B}ADAPTIVE ATTACK-PATH SCORING${R}   ${MUTED}· the swarm scores its own strategies with JEV${R}"
s 2.2
clear
p ""
p "  ${CYAN}${B}▶ finding${R}  ${WHITE}BOLA on /api/v2/order/{id}${R}   ${MUTED}· exploit agent generating candidate strategies…${R}"
p ""
s .5
p "  ${MUTED}candidate attack paths${R}"
p ""
printf '%b\n' "  ${PURPLE}${B}① ${R}${WHITE}IDOR → id-harvest → replay${R}          ${MUTED}httpreq · httpreq · httpreq${R}"; s .4
printf '%b\n' "  ${PURPLE}${B}② ${R}${WHITE}JWT forge (alg:none) → takeover${R}     ${MUTED}jwt · httpreq${R}"; s .4
printf '%b\n' "  ${PURPLE}${B}③ ${R}${WHITE}Mass assignment → role=admin${R}        ${MUTED}httpreq${R}"; s .4
printf '%b\n' "  ${PURPLE}${B}④ ${R}${WHITE}Verbose-error probe${R}                  ${MUTED}httpx${R}"; s .8
clear
p ""
p "  ${GREEN}${B}◆ JEV${R}  ${WHITE}scoring strategies against live state${R}   ${MUTED}· one typed pass · P(highest-value move)${R}"
p ""
s .5
sc(){ printf '%b\n' "  ${MUTED}score ${R}$2${B}%s${R}  $2%s${R}  ${MUTED}%s${R}"; }
printf '%b\n' "  ${MUTED}score ${R}${GREEN}${B}0.92${R}  ${GREEN}▓▓▓▓▓▓▓▓▓░${R}  ${WHITE}① IDOR → id-harvest → replay${R}   ${GREEN}${B}◀ pursue first${R}"; s .5
printf '%b\n' "  ${MUTED}score ${R}${GREEN}0.78${R}  ${GREEN}▓▓▓▓▓▓▓░░░${R}  ${WHITE}② JWT forge → takeover${R}"; s .4
printf '%b\n' "  ${MUTED}score ${R}${AMBER}0.61${R}  ${AMBER}▓▓▓▓▓▓░░░░${R}  ${WHITE}③ Mass assignment${R}"; s .4
printf '%b\n' "  ${MUTED}score ${R}${RED}0.12${R}  ${RED}▓░░░░░░░░░${R}  ${MUTED}④ Verbose-error probe${R}"; s 1.0
clear
p ""
p "  ${GREEN}${B}▶ pursuing ① IDOR → id-harvest → replay${R}   ${MUTED}(score 0.92)${R}"
p ""
printf '%b\n' "  ${GREEN}✓${R} ${WHITE}POST /login${R}                 ${MUTED}captured tok${R}"; s .45
printf '%b\n' "  ${GREEN}✓${R} ${WHITE}GET /order/2 as victim${R}      ${GREEN}200 — other user's order${R}"; s .45
printf '%b\n' "  ${RED}${B}●${R} ${RED}${B}CRITICAL${R} ${WHITE}BOLA account takeover confirmed${R}"; s .6
p ""
p "  ${AMBER}${B}pheromone signature${R}  ${AMBER}▓▓▓▓▓▓▓▓▓▓${R} ${GREEN}${B}1.0${R}   ${MUTED}← success × score reinforces the winning strategy${R}"
s 1.2
clear
p ""
p "  ${AMBER}${B}◢ the swarm learns which strategies land — and pours effort into them.${R}"
p ""
p "  ${GREEN}${B}score → signal → pheromone → the swarm steers itself.${R}"
p ""
p "  ${MUTED}Pentest Swarm AI · autonomous API/web-app pentester · open source${R}"
p "  ${CYAN}${B}pentestswarm scan --swarm --jev-adaptive${R}"
p ""
s 3.0
