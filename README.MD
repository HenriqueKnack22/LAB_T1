
SSL usamos no dns_dot_query e no dns_query_Dot


UDP X DoT
udp é mais rapido mas tem menos privacidade
x
DoT é mais lente, mas é criptografado e tem overhead

  python3 main.py                          →  auditoria_bloqueio.csv
  python3 main.py --domain www.google.com  →  auditoria_bloqueio.csv
  python3 main.py --benchmark              →  resultados.csv
  python3 main.py --dot                    →  comparacao_udp_dot.csv