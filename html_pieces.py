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
  margin-top: 6px;
}

.col-75 {
  float: left;
  width: 75%;
  margin-top: 6px;
}

/* Clear floats after the columns */
.row:after {
  content: "";
  display: table;
  clear: both;
}

/* Responsive layout - when the screen is less than 600px wide, make the two columns stack on top of each other instead of next to each other */
@media screen and (max-width: 600px) {
  .col-25, .col-75, input[type=submit] {
    width: 100%;
    margin-top: 0;
  }
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
        <a href="/tcp">TCP</a>
        <a href="/udp">UDP</a>
        <a href="/sctp">SCTP</a>
        <a href="/ip">IP</a>
        <a href="/full">Full protocol stack</a>
        <a href="/test">Test page</a>
        <br/>
    '''

FORM = '''
<div class="container">
  <form action="/test" method="post">
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
<br/>
<p>Samples</p>
<div class="container">
  <div class="row">
    <div class="col-25">
      HTML GET example
    </div>
    <div class="col-75">
      474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a
    </div>
  </div>
</div>

        <p>sample:</p>
                </br>
                        <p>474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a</p>
                        '''



