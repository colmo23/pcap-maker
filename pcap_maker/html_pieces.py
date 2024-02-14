CSS = '''
* {
  box-sizing: border-box;
}

input[type=text], select, textarea {
  width: 100%;
  padding: 12px;
  border: 1px solid #ccc;
  border-radius: 4px;
  resize: vertical;
}

label {
  padding: 12px 12px 12px 0;
  display: inline-block;
}

input[type=submit] {
  background-color: #04AA6D;
  color: white;
  padding: 12px 20px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  float: right;
}

input[type=submit]:hover {
  background-color: #45a049;
}

.container {
  border-radius: 5px;
  background-color: #f2f2f2;
  padding: 20px;
}

.col-25 {
  float: left;
  width: 25%;
  margin-top: 10px;
}

.col-75 {
  float: left;
  width: 75%;
  margin-top: 10px;
}
.info {
  text-align: center;
}

/* Clear floats after the columns */
.row:after {
  content: "";
  display: table;
  clear: both;
}
.header_links {
  border-radius: 5px;
  background-color: #90EE90;
  padding: 10px;
}
.col-20 {
  float: left;
  width: 20%;
  margin-top: 6px;
}

/* Responsive layout - when the screen is less than 600px wide, make the two
   columns stack on top of each other instead of next to each other */
@media screen and (max-width: 600px) {
  .col-25, .col-75, input[type=submit] {
    width: 100%;
    margin-top: 0;
  }
}

.wrapdiv {
  word-wrap: break-word;
}
'''
HEADER = '''<!DOCTYPE html>
<html>
<head>
<style>
%s
</style>
</head> ''' % CSS

TOP_LINKS = '''
 <div class="header_links">
   <div class="row">
    <div class="col-20">
        <a href="/tcp">TCP</a>
    </div>
    <div class="col-20">
        <a href="/udp">UDP</a>
   </div>
    <div class="col-20">
        <a href="/sctp">SCTP</a>
    </div>
    <div class="col-20">
        <a href="/sccp">SCCP</a>
    </div>
    <div class="col-20">
        <a href="/tcap">TCAP</a>
    </div>
    <div class="col-20">
        <a href="/ip">IP</a>
    </div>
    <div class="col-20">
        <a href="/ethernet">Ethernet</a>
    </div>
    <div class="col-20">
        <a href="/full">Full protocol stack</a>
    </div>
   </div>
  </div>
        <br/>
<br/>
<br/>
    '''

INFO = '''
<div class="container">
<div class="info">
This site takes hex dumps of network messages and generates a pcap file.
</div>
</div>
<div class="container">
<div class="info">
A pcap file can be viewed via the Wireshark desktop application, see <a href="https://www.wireshark.org/">www.wireshark.org</a>
</div>
</div>
'''


FORM_TCP = '''
<div class="container">
  <form action="/tcp" method="post">
 <div class="row">
    <div class="col-25">
      <label for="dport">Destination port</label>
    </div>
    <div class="col-75">
      <input type="text" id="dport" name="dport" value="80" type="number" min="0" step="1" max="65535" size="5">
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      <label for="tcphex">TCP hext payload</label>
    </div>
    <div class="col-75">
      <textarea id="tcphex" name="tcphex" placeholder="TCP hex (see below for examples)" style="height:200px"></textarea>
    </div>
  </div>
  <br>
  <div class="row">
    <input type="submit" value="Generate pcap">
  </div>
  </form>
</div>
<br/>
<br/>
<p>Samples</p>
<div class="container">
  <div class="row">
    <div class="col-25">
      HTTP GET example
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      HTTP2 example
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         485454502f312e312031303120537769746368696e672050726f746f636f6c730d0a436f6e6e656374696f6e3a20557067726164650d0a557067726164653a206832630d0a0d0a000012040000000000000300000064000400100000000100002000
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      MMS example
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         504f5354202f6d6d732f776170656e6320485454502f312e310d0a486f73743a2031302e3230302e3130302e30300d0a507261676d613a206e6f2d63616368650d0a4163636570743a206170706c69636174696f6e2f766e642e7761702e6d6d732d6d6573736167650d0a4163636570742d436861727365743a202a0d0a582d5761702d50726f66696c653a20687474703a2f2f6970686f6e656d6d732e6170706c652e636f6d2f6970686f6e652f756170726f662d324d422e7264660d0a4163636570742d4c616e67756167653a202a0d0a4163636570742d456e636f64696e673a206964656e746974790d0a436f6e74656e742d547970653a206170706c69636174696f6e2f766e642e7761702e6d6d732d6d6573736167650d0a436f6e74656e742d4c656e6774683a203630360d0a557365722d4167656e743a206950686f6e654f532f31362e332e3120283230443637290d0a6e756c6c3a20687474703a2f2f6d6d732e677072732e6162636465662e636f6d2f0d0a782d75702d7375626e6f3a20313238363830303030305f616263646566707573682e677072732e6162636465662e636f6d0d0a782d75702d63616c6c696e672d6c696e652d69643a2031393035353430303030300d0a782d75702d63682d7367736e69703a2037342e3139382e37302e3031330d0a782d75702d7261742d747970653a2030360d0a782d75702d737562736372696265722d636f733a2030310d0a43616368652d436f6e74726f6c3a206e6f2d63616368650d0a0d0a8c8098313637373030303030302d3135008d9397178331323839323434303030302f545950453d504c4d4e0097178331353139383032303030302f545950453d504c4d4e0097178331393035393231303030302f545950453d504c4d4e0097178331393035353431303030302f545950453d504c4d4e0097178331323839343432303030302f545950453d504c4d4e00890181841bb3896170706c69636174696f6e2f736d696c008a302e736d696c00021a822a6170706c69636174696f6e2f736d696c00c022302e736d696c003c736d696c3e0a3c686561643e0a3c6c61796f75743e0a203c726f6f742d6c61796f75742f3e0a3c726567696f6e2069643d22546578742220746f703d2237302522206c6566743d22302522206865696768743d22333025222077696474683d223130302522206669743d227363726f6c6c222f3e0a3c726567696f6e2069643d22496d6167652220746f703d22302522206c6566743d22302522206865696768743d22373025222077696474683d223130302522206669743d226d656574222f3e0a3c2f6c61796f75743e0a3c2f686561643e0a3c626f64793e0a3c706172206475723d22313073223e0a3c74657874207372633d22746578745f302e7478742220726567696f6e3d2254657874222f3e0a3c2f7061723e0a3c2f626f64793e0a3c2f736d696c3e0a31330f8385746578745f302e7478740081eaae0f8186746578745f302e7478740081eac02230008e746578745f302e7478740054657374206d6573736167652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e20f09f98adf09f98a2f09f98adf09f98a2
      </div>
    </div>
  </div>
</div>
'''


FORM_UDP = '''
<div class="container">
  <form action="/udp" method="post">
 <div class="row">
    <div class="col-25">
      <label for="dport">Destination port</label>
    </div>
    <div class="col-75">
      <input type="text" id="dport" name="dport" value="161" type="number" min="0" step="1" max="65535" size="5">
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      <label for="tcphex">UDP hex payload</label>
    </div>
    <div class="col-75">
      <textarea id="tcphex" name="udphex" placeholder="UDP hex (see below for examples)" style="height:200px"></textarea>
    </div>
  </div>
  <br>
  <div class="row">
    <input type="submit" value="Generate pcap">
  </div>
  </form>
</div>
<br/>
<br/>
<p>Samples</p>
<div class="container">
  <div class="row">
    <div class="col-25">
      SNMP GET (use dest port of 161)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         307902010004067075626c6963a26c0201290201000201003061302106122b06010401817d0840040201070a86deb738040b3137322e33312e31392e32302306122b06010401817d0840040201070a86deb736040d3235352e3235352e3235352e30301706122b06010401817d0840040201050a86deb960020101
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      GTP v1 Create PDP Context Request (use dest port of 2123)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         321000970000000000fe00000272020301000000f00372f230fffeff0e5d0ffc10372f000011372f00001405800002f121830010036d6d73086d796d6574656f7202696584002280c0230b0100000b026d790377617080211001000010810600000000830600000000850004d481410d850004d48141178600079153830000000087000c0223621f9396585874fbffff970001029a00085389011058985321
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      GTP v1 - small example (use dest port of 2123)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         3210001c000000009dbc00000215807922060357f00ffc108513c02a
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      DNS request (use dest port of 53)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         43130100000100000000000003616f6c03636f6d0000010001
      </div>
    </div>
  <div class="row">
    <div class="col-25">
      SIP request
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         5245474953544552207369703a742e766f6e63702e636f6d3a3130303030205349502f322e300d0a4d61782d466f7277617264733a2037300d0a436f6e74656e742d4c656e6774683a20300d0a5669613a205349502f322e302f554450203139322e3136382e312e36343a31303030303b6272616e63683d7a39684734624b3538626632303161300d0a43616c6c2d49443a206531383762616265356139313761613564653036613430623031663539623235403139322e3136382e312e36340d0a46726f6d3a2022313631373837363631313122203c7369703a313631373837363631313140742e766f6e63702e636f6d3a31303030303e3b7461673d3966626233656339653439623864350d0a546f3a2022313631373837363631313122203c7369703a313631373837363631313140742e766f6e63702e636f6d3a31303030303e0d0a435365713a203734353638343531352052454749535445520d0a436f6e746163743a2022313631373837363631313122203c7369703a3136313738373636313131403139322e3136382e312e36343a31303030303b7472616e73706f72743d7564703e3b657870697265733d32300d0a416c6c6f773a20494e564954452c2041434b2c2043414e43454c2c204259452c204e4f544946592c2052454645522c204f5054494f4e532c205550444154452c20505241434b0d0a417574686f72697a6174696f6e3a44696765737420726573706f6e73653d223766366565643731666364393235356266396666613537356634343631373035222c757365726e616d653d223136313738373636313131222c7265616c6d3d223231362e3131352e32302e313433222c6e6f6e63653d2231353330353333343134222c616c676f726974686d3d4d44352c7572693d227369703a742e766f6e63702e636f6d3a3130303030220d0a557365722d4167656e743a2056445632312030303144443932453446363120322e382e315f312e342e37204c776f6f456b334743442f62636d3030314444393245344636312e786d6c0d0a0d0a
      </div>
    </div>
  </div>
</div>
  </div>
</div>
'''


FORM_SCTP = '''
<div class="container">
  <form action="/sctp" method="post">
 <div class="row">
    <div class="col-25">
      <label for="sport">Source port</label>
    </div>
    <div class="col-75">
      <input type="text" id="sport" name="sport" value="2905" type="number" min="0" step="1" max="65535" size="5">
    </div>
  </div>
 <div class="row">
    <div class="col-25">
      <label for="dport">Destination port</label>
    </div>
    <div class="col-75">
      <input type="text" id="dport" name="dport" value="2905" type="number" min="0" step="1" max="65535" size="5">
    </div>
  </div>
 <div class="row">
    <div class="col-25">
      <label for="pid">Protocol Id (3 means M3UA, 2 means M2UA)</label>
    </div>
    <div class="col-75">
      <input type="text" id="pid" name="protocol" value="3" type="number" min="0" step="1" max="65535" size="5">
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      <label for="tcphex">SCTP hex payload</label>
    </div>
    <div class="col-75">
      <textarea id="hex" name="sctphex" placeholder="SCTP hex (see below for examples)" style="height:200px"></textarea>
    </div>
  </div>
  <br>
  <div class="row">
    <input type="submit" value="Generate pcap">
  </div>
  </form>
</div>
<br/>
<br/>
<p>Samples</p>
<div class="container">
  <div class="row">
    <div class="col-25">
      M3UA DATA (use dest port of 2905)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         0100030100000008
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      m3ua/sccp/tcap begin/ati
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         0100010100000094000600080000003302100081000003e8000003e903000013098103101c0d120600710479510001000016000c12930011045383171111110150624e4804733b33c96b1e281c060700118605010101a011600f80020780a109060704000001001d036c26a124020147020147301ca00a800844500101000016f0a10480008100830891538307000000f1000000
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      M2UA/SCCP/TCAP/USSD (use protocol of 2)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         010006010000009c0300009283286204210900030d180a129300110472281906000b12060011047228196041066c626a48042f3b46026b3a2838060700118605010101a02d602b80020780a109060704000001001302be1a2818060704000001010101a00da00b80099656051124006913f66c26a12402010102013b301c04010f040eaa180da682dd6c31192d36bbdd468007917267415827f20000
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      M2UA/MTP3/SCCP/ANSI TCAP/SMS Delivery Point to Point (OTA) (use protocol of 2)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         0100060100000060000100080000003e0300004e830a800400090003070b04430a0008044312000c35e233c70400000000e82be929cf0100d1020935f2209f69009f74009f81000108880516193204009f814101019f81430522222222220000
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      M2UA/MTP3/SCCP/TCAP/Camel Initial DP Arg (use protocol of 2)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         01000601000000cc030000c1833001e8430981030d170a129200120422705700400a129200120422705700709c6281994804070004006b1a2818060700118605010101a00d600ba1090607040000010032016c75a173020101020100306b80016e8208839021721090000f830303975785010a8c06831407010900bb0580038090a39c01029d068314070109009e0203619f320806079209100491f9bf35038301119f360513fa3d3dea9f37069122705700709f39080250114231016500bf3b088106912270570070000000
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      M2UA/MTP3/SCCP/TCAP/GSM Process USSD (use protocol of 2)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         010006010000009c0300009283286204210900030d180a129300110472281906000b12060011047228196041066c626a48042f3b46026b3a2838060700118605010101a02d602b80020780a109060704000001001302be1a2818060704000001010101a00da00b80099656051124006913f66c26a12402010102013b301c04010f040eaa180da682dd6c31192d36bbdd468007917267415827f20000
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      Diameter 3GPP Authentication Information Request (use protocol of 46)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         010000d4c000013e0100002300002dc300043547000001150000000c0000000000000108000000346f7269676974686f73742e6570632e6d6e633035312e6d63633236322e336770706e6574776f726b2e6f726700000128000000296570632e6d6e633035312e6d63633236322e336770706e6574776f726b2e6f72670000000000011b000000296570632e6d6e633030392e6d63633230382e336770706e6574776f726b2e6f72670000000000000100000017353432393931313131313131313131000000057f8000000f000028af62125000
      </div>
    </div>
  </div>
</div>
'''

FORM_TCAP = '''
<div class="container">
  <form action="/tcap" method="post">
  <div class="row">
    <div class="col-25">
      <label for="tcphex">TCAP hex payload</label>
    </div>
    <div class="col-75">
      <textarea id="hex" name="tcaphex" placeholder="TCAP hex (see below for examples)" style="height:200px"></textarea>
    </div>
  </div>
  <br>
  <div class="row">
    <input type="submit" value="Generate pcap">
  </div>
  </form>
</div>
<br/>
<br/>
<p>Samples</p>
<div class="container">
  <div class="row">
    <div class="col-25">
      TCAP Begin MAP MO FSM
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         6259480349d2286b1a2818060700118605010101a00d600ba1090607040000010015036c36a13402010102012e302c8407911808390100008207911808390100010418b5000c915383060020900000a70be8329bfd06dddf723619
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      TCAP End Return Error
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         643c49035645066b262824060700118605010101a0196117a109060704000001001503a203020100a305a1030201006c0da30b02010102012030030a0105
      </div>
    </div>
  </div>
</div>
'''

FORM_SCCP = '''
<div class="container">
  <form action="/sccp" method="post">
  <div class="row">
    <div class="col-25">
      <label for="tcphex">SCCP hex payload</label>
    </div>
    <div class="col-75">
      <textarea id="hex" name="sccphex" placeholder="SCCP hex (see below for examples)" style="height:200px"></textarea>
    </div>
  </div>
  <br>
  <div class="row">
    <input type="submit" value="Generate pcap">
  </div>
  </form>
</div>
<br/>
<br/>
<p>Samples</p>
<div class="container">
  <div class="row">
    <div class="col-25">
      TCAP Begin MAP MO FSM
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         0900030e190b12080a12041808390100000b12080a12045383160002005b6259480349d2286b1a2818060700118605010101a00d600ba1090607040000010015036c36a13402010102012e302c8407911808390100008207911808390100010418b5000c915383060020900000a70be8329bfd06dddf723619
      </div>
    </div>
  <div class="row">
    <div class="col-25">
      TCAP Return Error
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         0900030e190b12080a12041808390100000b12080a12045383160002005b643c49035645066b262824060700118605010101a0196117a109060704000001001503a203020100a305a1030201006c0da30b02010102012030030a0105
      </div>
    </div>
    </div>
  <div class="row">
    <div class="col-25">
      TCAP Response Provide Roaming Number
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         0980030d170a120600120454045100000a120700120474141700004c644a49049b0001256b2a2828060700118605010101a01d611b80020780a109060704000001000303a203020100a305a1030201006c80a212020101300d020104300804069174141700000000
      </div>
    </div>
  </div>
</div>
'''
FORM_IP = '''
<div class="container">
  <form action="/ip" method="post">
 <div class="row">
    <div class="col-25">
      <label for="pid">Protocol</label>
    </div>
    <div class="col-75">
      <input type="text" id="pid" name="protocol" value="3" type="number" min="0" step="1" max="65535" size="5">
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      <label for="tcphex">IP hex payload</label>
    </div>
    <div class="col-75">
      <textarea id="hex" name="iphex" placeholder="IP hex (see below for examples)" style="height:200px"></textarea>
    </div>
  </div>
  <br>
  <div class="row">
    <input type="submit" value="Generate pcap">
  </div>
  </form>
</div>
<br/>
<br/>
<p>Samples</p>
<div class="container">
  <div class="row">
    <div class="col-25">
      SCTP/M3UA DATA (use protocol of 132)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         189f0b5add68d33d40ed9bde00030018d42b489200000000000000030100030400000008
      </div>
    </div>
  </div>
</div>
'''

FORM_FULL = '''
<div class="container">
  <form action="/full" method="post">
 <div class="row">
    <div class="col-25">
      <label for="ltype">Link Type</label>
    </div>
    <div class="col-75">
      <input type="text" id="ltype" name="linktype" value="1" type="number" min="0" step="1" max="255" size="3">
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      <label for="tcphex">Full hex payload</label>
    </div>
    <div class="col-75">
      <textarea id="hex" name="fullhex" placeholder="Full hex (see below for examples)" style="height:200px"></textarea>
    </div>
  </div>
  <br>
  <div class="row">
    <input type="submit" value="Generate pcap">
  </div>
  </form>
</div>
<br/>
<br/>
<p>Samples</p>
<div class="container">
  <div class="row">
    <div class="col-25">
      Ethernet/io/sctp/m3ua <br/>(use linktype of 1)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         00005096523a0026cb39f4c0080045000068da010000fa844c7e585206860aad300d189f0b5add68d33d40ed9bde00030018d42b48920000000000000003010003040000000800030030d42b489300000001000000030100000100000020000d000800010002001100080000000d0006000800000456
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      MTP3/SCCP/BSSAP/GSM  <br/>(use linktype of 141)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         03443322db0693150300011f01001c03c504066004020005815e0581020055207e090005060027004004f1
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      MTP2/MTP3/ISUP IAM  <br/> (use linktype of 140)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         1d1d2085024000900e00011100000a03020907039040380982990a06031317734508007989
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      Linux Cooked Capture/IP/UPD/VXLAN....  <br/> (use linktype of 113)
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         0000030400060000000000000000080045000075863140004011b6447f0000017f000001169d12b50061fe740800000000000100620deb01aa1efaaed0f78fdc080045000043000000004011a3103953300202136c329c40084b002f79e74822002308ca5b2974d6130056000d001806f2100fa106f210002e70035200010006030001000c00000000000000000000000000000000
      </div>
    </div>
  </div>
</div>
'''


FORM_ETHERNET = '''
<div class="container">
  <form action="/ethernet" method="post">
  <div class="row">
    <div class="col-25">
      <label for="ethernethex">Ethernet hex payload</label>
    </div>
    <div class="col-75">
      <textarea id="hex" name="ethernethex" placeholder="Ethernet hex (see below for examples)" style="height:200px"></textarea>
    </div>
  </div>
  <br>
  <div class="row">
    <input type="submit" value="Generate pcap">
  </div>
  </form>
</div>
<br/>
<br/>
<p>Samples</p>
<div class="container">
  <div class="row">
    <div class="col-25">
      ip/sctp/m3ua <br/>
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         45000068da010000fa844c7e585206860aad300d189f0b5add68d33d40ed9bde00030018d42b48920000000000000003010003040000000800030030d42b489300000001000000030100000100000020000d000800010002001100080000000d0006000800000456
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-25">
      ip/tcp/http <br/>
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         4500005e000000004006526d0a0a0a0a0a0a0a1003e80050deadbeef000000005002ffffe6b90000474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a
      </div>
    </div>
  </div>
</div>
'''
