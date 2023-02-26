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
        <a href="/ip">IP</a>
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
      HTML GET example
    </div>
    <div class="col-75">
      <div class="wrapdiv">
         474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a
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
</div>
'''
