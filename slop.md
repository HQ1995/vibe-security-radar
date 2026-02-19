# Slop

This collection is limited to only include the reports that were submitted as security vulnerabilities
to the [curl](https://curl.se) [bug-bounty program on Hackerone](https://hackerone.com/curl).

Several other issues not included here are highly suspcious as well.

## Reports

1. [Critical] Curl CVE-2023-38545 vulnerability code changes are disclosed on the internet. [#2199174](https://hackerone.com/reports/2199174)
2. Buffer Overflow Vulnerability in WebSocket Handling [#2298307](https://hackerone.com/reports/2298307)
3. Exploitable Format String Vulnerability in curl_mfprintf Function [#2819666](https://hackerone.com/reports/2819666)
4. Buffer overflow in strcpy [#2823554](https://hackerone.com/reports/2823554)
5. Buffer Overflow Vulnerability in strcpy() Leading to Remote Code Execution [#2871792](https://hackerone.com/reports/2871792)
6. Buffer Overflow Risk in Curl_inet_ntop and inet_ntop4 [#2887487](https://hackerone.com/reports/2887487)
7. bypass of this Fixed #2437131 [ Inadequate Protocol Restriction Enforcement in curl ] [#2905552](https://hackerone.com/reports/2905552)
8. Hackers Attack Curl Vulnerability Accessing Sensitive Information [#2912277](https://hackerone.com/reports/2912277)
9. ("possible") UAF [#2981245](https://hackerone.com/reports/2981245)
10. Path Traversal Vulnerability in curl via Unsanitized IPFS_PATH Environment Variable [#3100073](https://hackerone.com/reports/3100073)
11. Buffer Overflow in curl MQTT Test Server (tests/server/mqttd.c) via Malicious CONNECT Packet [#3101127](https://hackerone.com/reports/3101127)
12. Use of a Broken or Risky Cryptographic Algorithm (CWE-327) in libcurl [#3116935](https://hackerone.com/reports/3116935)
13. Double Free Vulnerability in `libcurl` Cookie Management (`cookie.c`) [#3117697](https://hackerone.com/reports/3117697)
14. HTTP/2 CONTINUATION Flood Vulnerability [#3125820](https://hackerone.com/reports/3125820)
15. HTTP/3 Stream Dependency Cycle Exploit [#3125832](https://hackerone.com/reports/3125832)
16. Memory Leak [#3137657](https://hackerone.com/reports/3137657)
17. Memory Leak in libcurl via Location Header Handling (CWE-770) [#3158093](https://hackerone.com/reports/3158093)
18. Stack-based Buffer Overflow in TELNET NEW_ENV Option Handling [#3230082](https://hackerone.com/reports/3230082)
19. HTTP Proxy Bypass via `CURLOPT_CUSTOMREQUEST` Verb Tunneling [#3231321](https://hackerone.com/reports/3231321)
20. Use-After-Free in OpenSSL Keylog Callback via SSL_get_ex_data() in libcurl [#3242005](https://hackerone.com/reports/3242005)
21. HTTP Request Smuggling Vulnerability Analysis - cURL Security Report [#3249936](https://hackerone.com/reports/3249936)
22. Disk Space Exhaustion leading to a Denial of Service (DoS) [#3250490](https://hackerone.com/reports/3250490)
23. Vulnerability Report: Public Exposure of Security Audit File [#3272982](https://hackerone.com/reports/3272982)
24. Vulnerability Report: Local File Disclosure via file:// Protocol in cURL [#3293884](https://hackerone.com/reports/3293884)
25. Exposure of Hard-coded Private Keys and Credentials in curl Source Repository (CWE-321) [#3295650](https://hackerone.com/reports/3295650)
26. TOCTOU Race Condition in HTTP/2 Connection Reuse Leads to Certificate Validation Bypass [#3335085](https://hackerone.com/reports/3335085)
27. Stack Buffer Overflow in cURL Cookie Parsing Leads to RCE [#3340109](https://hackerone.com/reports/3340109)
28. Timing Attack Vulnerability in curl Digest Authentication via Non-Constant-Time String Comparison [#3346118](https://hackerone.com/reports/3346118)
29. Buffer Overflow in WebSocket Handshake (lib/ws.c:1287) [#3392174](https://hackerone.com/reports/3392174)
30. Use of Deprecated strcpy() with Fixed-Size Buffers in Progress Time Formatting [#3395218](https://hackerone.com/reports/3395218)
31. Use of Deprecated strcpy() with User-Controlled Environment Variable in Memory Debug Initialization [#3395227](https://hackerone.com/reports/3395227)
32. Integer Overflow to Heap Overflow in DoH Response Handling [#3399774](https://hackerone.com/reports/3399774)
33. CURLX_SET_BINMODE(NULL) can call fileno(NULL) and cause undefined behavior / crash [#3400831](https://hackerone.com/reports/3400831)
34. Logical Flaw in curl_url_set Leads to Inconsistent Query Parameter Encoding [#3403880](https://hackerone.com/reports/3403880)
35. Unsafe use of strcpy in Curl_ldap_err2string (packages/OS400/os400sys.c) — stack-buffer-overflow (PoC + ASan) [#3418528](https://hackerone.com/reports/3418528)
36. Arbitrary Configuration File Inclusion: via External Control of File Name or Path [#3418646](https://hackerone.com/reports/3418646)
37. Title: Use-After-Free in cURL Test Suite via Improper Cleanup of Global Handle [#3452725](https://hackerone.com/reports/3452725)
38. Stack Buffer Overflow in cURL wolfSSL Backend (lib/vtls/wolfssl.c) [#3459636](https://hackerone.com/reports/3459636)
39. Buffer Overflow in cURL Internal printf Function [#3462525](https://hackerone.com/reports/3462525)
40. Path Traversal Bypass in file:// URLs Due to Incomplete URL-Encoded Path Normalization [#3465094](https://hackerone.com/reports/3465094)
41. Curl Alt-Svc Parser Stack Buffer Overflow [#3466883](https://hackerone.com/reports/3466883)
42. Heap Overflow in cURL AmigaOS Socket Implementation [#3466896](https://hackerone.com/reports/3466896)
43. Heap buffer overflow in Curl_ipv4_resolve_r due to incorrect buffer alignment and size calculation on AmigaOS [#3468410](https://hackerone.com/reports/3468410)
44. Heap Buffer Over-Read via Malicious SMB Server READ_ANDX Response [#3470095](https://hackerone.com/reports/3470095)
45. A logic error in detect_proxy caused truncation of environment variable names for long protocol schemes. [#3473182](https://hackerone.com/reports/3473182)
47. Heap Out-of-Bounds Read in lib/http2.c via Malformed PUSH_PROMISE Headers [#3506159](https://hackerone.com/reports/3506159)
48. libcurl: Improper Authentication State Management on Cross-Protocol Redirects [#3514263](https://hackerone.com/reports/3514263)
49. Cookie Max-Age Integer Overflow Vulnerability [#3516186](https://hackerone.com/reports/3516186)
50. Cookie Replacement Use-After-Free Vulnerability [#3516202](https://hackerone.com/reports/3516202)

## Policy

Our current policy says that we *instantly* ban all reporters submitting AI slop.

![SLOP](https://gist.github.com/user-attachments/assets/e43ee5e8-9615-4fc5-b0aa-b92e6c99dec6)
