

function hexToAscii(str){
    hexString = str;
    strOut = '';
        for (x = 0; x < hexString.length; x += 2) {
	    charCodeInt = parseInt(hexString.substr(x, 2), 16);
	    if ((charCodeInt >= 32) && (charCodeInt <= 126)){
                strOut += String.fromCharCode(parseInt(hexString.substr(x, 2), 16));
	    } else {
                strOut += ".";
            }
        }
    return strOut;    
}

console.log(hexToAscii("0001102030405060708090a0b0c0d0e0f0"))
