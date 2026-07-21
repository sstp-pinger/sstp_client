# Attribution

The SSTP and PPP protocol logic in this package (packet framing, the LCP/IPCP
configure-negotiation state machine, MSCHAPv2 response/authenticator derivation,
and the SSTP crypto binding) was derived by studying the protocol handling in:

**Open SSTP Client** by KOBAYASHI Ittoku
https://github.com/kittoku/Open-SSTP-Client

That project is licensed under the MIT License. Its logic was translated to
idiomatic asynchronous Dart rather than ported line-by-line, but it served as
the working specification for correct behaviour against SoftEther / VPN Azure
servers. The original license notice is reproduced below.

---

MIT License

Copyright (c) 2019 KOBAYASHI Ittoku

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Additional protocol references:
- MS-SSTP: Secure Socket Tunneling Protocol
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/
- RFC 1661 (PPP), RFC 1994 (CHAP), RFC 2759 (MSCHAPv2), RFC 3079 (MPPE keys)
