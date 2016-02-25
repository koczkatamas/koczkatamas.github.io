function strToBytes(str){
  var bytes = [];

  for (var i = 0; i < str.length; i++)
    bytes.push(str.charCodeAt(i));

  return bytes;
}

function bytesToStr(bytes){
  var str = '';

  for (var i = 0; i < bytes.length; i++)
    str += String.fromCharCode(bytes[i])

  return str;
}

function join(array, separator){
  separator = separator || ', ';

  var str = '';

  for (var i = 0; i < array.length; i++){
    if(str != '')
      str += separator;
    str += array[i];
  }

  return str;
}

function strToBase64(bytes){ return btoa(bytes); }
function bytesToBase64(bytes){ return strToBase64(bytesToStr(bytes)); }

function base64ToStr(base64str){ return atob(base64str.replace(/-/g, '+').replace(/_/g, '/')); }
function base64ToBytes(str){ return strToBytes(base64ToStr(str)); }

function base32ToStr(base32str){ return bytesToStr(base32ToBytes(base32str)); }
function base32ToBytes(str){
  str = str.replace(/[\s=]+/g, '');

  var bitCount = 0, bitData = 0, bytes = [];
  for (var i = 0; i < str.length; i++) {
    putBits(5, _base32CharcodeToInt(str.charCodeAt(i)));
  }
  return bytes;

  function putBits(cnt, data) {
    bitData = (bitData << cnt) | data;
    bitCount += cnt;
    while (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((bitData >> bitCount) & 0xff);
    }
  }
}

function strToBase32(bytes){ return bytesToBase32(strToBytes(bytes)); }

function bytesToBase32(bytes) {
  var result = '';
  var bitData = 0, bitCount = 0;
  for (var i = 0; i < bytes.length; i++) {
    putBits(8, bytes[i]);
  }
  if (bitCount > 0) putBits(5, 0);
  while (result.length % 8 > 0) result += '=';
  return result;

  function putBits(cnt, data) {
    bitData = (bitData << cnt) | data;
    bitCount += cnt;
    while (bitCount >= 5) {
      bitCount -= 5;
      result += String.fromCharCode(_base32IntToCharcode((bitData >> bitCount) & 0x1f));
    }
  }
}

function _base32CharcodeToInt(chCode) {
  if (chCode >= 65 && chCode <= 90) return chCode - 65;        // A-Z -> 0-25
  if (chCode >= 97 && chCode <= 122) return chCode - 97;       // a-z -> 0-25
  if (chCode >= 50 && chCode <= 55) return chCode - 50 + 26;   // 2-7 -> 26-31
  throw new Error('Base32 invalid charcode')
}
function _base32IntToCharcode(i) {
  if (i >= 0 && i <= 25) return i + 65;
  if (i >= 26 && i <= 31) return i - 26 + 50;
  throw new Error('Base32 invalid int')
}

function bytesToHex(bytes, separator){
  separator = separator || '';
  return bytes.map(function(x){ return padLeft(x.toString(16),'00'); }).join(separator);
}

function strToHex(str, separator){ return bytesToHex(strToBytes(str), separator); }
function hexToStr(hexStr){ return bytesToStr(hexToBytes(hexStr)); }

function hexToBytes(str){
  var filteredStr = str.toLowerCase().replace(/[^0-9a-f]/g, '');
  if(filteredStr.length % 2 == 1)
    filteredStr = '0' + filteredStr;

  var bytes = [];
  for(var i = 0; i < filteredStr.length; i += 2)
    bytes.push(parseInt(filteredStr.substr(i, 2), 16));
  return bytes;
}

function bytesToOct(bytes, separator){
  separator = separator || '';
  return bytes.map(function(x){ return padLeft(x.toString(8),'000'); }).join(separator);
}

function octToBytes(str){
  var filteredStr = str.replace(/[^0-7]/g, '');

  var bytes = [];
  for(var i = 0; i < filteredStr.length; i += 3)
    bytes.push(parseInt(filteredStr.substr(i, 3), 8));
  return bytes;
}

function bytesToBinary(bytes){
  return join(bytes.map(function(x){ return padLeft(x.toString(2),'00000000'); }), ' ');
}

function binaryToBytes(str){
  var filteredStr = str.replace(/[^01]/g, '');

  var bytes = [];
  for(var i = 0; i < filteredStr.length; i += 8)
    bytes.push(parseInt(filteredStr.substr(i, 8), 2));
  return bytes;
}

function padLeft(str, padPattern){
  return String(padPattern + str).slice(-padPattern.length);
}

function htmlEncode(value){
  return $('<div/>').text(value).html();
}

function htmlDecode(value){
  return $('<div/>').html(value).text();
}

function reverse(str){
  return str.split("").reverse().join("");
}

function rotMod(c, n, base){
  var val = c - base + n;
  if(val < 0) val += 26;
  if(val > 25) val -= 26;
  return base + val;
}

function rot(str, n){
  var result = '';
  for(var i = 0; i < str.length; i++){
    var c = str.charCodeAt(i);
    if(97 <= c && c <= 122)
      c = rotMod(c, n, 97);
    else if(65 <= c && c <= 90)
      c = rotMod(c, n, 65);
    result += String.fromCharCode(c);
  }
  return result;
}

var morseTable = {
  A: '.-',
  B: '-...',
  C: '-.-.',
  D: '-..',
  E: '.',
  F: '..-.',
  G: '--.',
  H: '....',
  I: '..',
  J: '.---',
  K: '-.-',
  L: '.-..',
  M: '--',
  N: '-.',
  O: '---',
  P: '.--.',
  Q: '--.-',
  R: '.-.',
  S: '...',
  T: '-',
  U: '..-',
  V: '...-',
  W: '.--',
  X: '-..-',
  Y: '-.--',
  Z: '--..',
  0: '-----',
  1: '.----',
  2: '..---',
  3: '...--',
  4: '....-',
  5: '.....',
  6: '-....',
  7: '--...',
  8: '---..',
  9: '----.',
  '.': '.-.-.-',
  '?': '..--..',
  '\'': '.----.',
  '"': '.-..-.',
  '/': '-..-.',
  '@': '.--.-.',
  '=': '-...-',
  '$': '...-..-',
  '!': '---.',
  '?': '.-..-.',
  '(': '-.--.-',
  ')': '-.--.-',
  '[': '-.--.',
  ']': '-.--.-',
  '+': '.-.-.',
  '-': '-....-',
  '_': '..--.-',
  ':': '---...',
  ';': '-.-.-.',
  '\n': '.-.-'
};
var morseTableRev = Array();
for(var morseKey in morseTable)
  morseTableRev[morseTable[morseKey]] = morseKey;

function morseDecode(str){
  // \u2022 = bullet

  // \u2012 = figure dash
  // \u2013 = en dash
  // \u2014 = em dash
  // \u2015 = horizontal bar
  // \u2212 = minus sign
  str = str.replace(/[\u2022\*\+]/g, '.').replace(/[\u2012\u2013\u2014\u2015\u2212_]/g, '-');

  var parts = str.split(' ');
  var result = '';
  for(var i = 0; i < parts.length; i++){
    var value = morseTableRev[parts[i]];
    result += value ? value : parts[i];
  }
  return result;
}

function morseEncode(str){
  str = str.toUpperCase();

  var result = '';
  for(var i = 0; i < str.length; i++){
    var c = morseTable[str.charAt(i)];
    if(c)
      result += (result == '' ? '' : ' ') + c;
  }
  return result.replace(/\./g, '\u2022' /* bullet */).replace(/-/g, '\u2212' /* minus sign */);
}

function bytesToIntStr(bytes){
  return new BigInteger(bytesToHex(bytes),16).toString(10);
}

function intStrToBytes(intStr){
  return hexToBytes(new BigInteger(intStr, 10).toString(16));
}

function bytesToDecList(bytes){ return join(bytes, ' '); }
function decListToBytes(decList){ return /[0-9]+/g.matches(decList).map(function(x){ return parseInt(x); }); }

var urldecode = decodeURIComponent;
var urlencode = encodeURIComponent;

String.prototype.repeat = function(count) {
  if (count < 1) return '';
  var result = '', pattern = this.valueOf();
  while (count > 1) {
    if (count & 1) result += pattern;
    count >>= 1, pattern += pattern;
  }
  return result + pattern;
};

var hashInfos = {
  md5:       { algo: CryptoJS.algo.MD5,       hashLen: 16, bitLenSize:  8, blockSize:  64, littleEndian: true  },
  ripemd160: { algo: CryptoJS.algo.RIPEMD160, hashLen: 20, bitLenSize:  8, blockSize:  64, littleEndian: true  },
  sha1:      { algo: CryptoJS.algo.SHA1,      hashLen: 20, bitLenSize:  8, blockSize:  64, littleEndian: false },
  sha256:    { algo: CryptoJS.algo.SHA256,    hashLen: 32, bitLenSize:  8, blockSize:  64, littleEndian: false },
  sha512:    { algo: CryptoJS.algo.SHA512,    hashLen: 64, bitLenSize: 16, blockSize: 128, littleEndian: false }
};

function endiannessSwitch(num){
  return (num >>> 24) | ((num >>> 8) & 0xff00) | ((num & 0xff00) << 8) | (num << 24);
}

function lengthExtensionAttack(hashInfo, data, origSign, secretLen, appendText) {
  // create hash
  var hashAlgo = hashInfo.algo.create();

  // restore state
  var origSignWords = CryptoJS.enc.Latin1.parse(origSign).words;

  if(hashInfo.littleEndian)
    for(var i = 0; i < origSignWords.length; i++)
      origSignWords[i] = endiannessSwitch(origSignWords[i]);

  if(hashAlgo._hash.toX32) // 64-bit words
    for(var i = 0; i < origSignWords.length / 2; i++)
      hashAlgo._hash.words[i] = (CryptoJS.x64.Word.create(origSignWords[i * 2], origSignWords[i * 2 + 1]));
  else
    hashAlgo._hash.words = origSignWords;

  // append new text
  hashAlgo.update(appendText);

  // calculate byte lengths for <secret> + <data> + <padding> + <bit len of data>
  var byteLenWoPadding = secretLen + data.length + hashInfo.bitLenSize;
  var fullByteSize = ((Math.floor(byteLenWoPadding / hashInfo.blockSize) + 1) * hashInfo.blockSize);
  var paddingLen = fullByteSize - byteLenWoPadding;
  hashAlgo._nDataBytes += fullByteSize;

  // calculate new signature
  var newSignature = CryptoJS.enc.Latin1.stringify(hashAlgo.finalize());

  var bitLen = (data.length + secretLen) * 8;
  var bitLenStr = bytesToStr(new Array(0, 0, 0, 0, bitLen >>> 24, bitLen >>> 16 & 0xff, bitLen >>> 8 & 0xff, bitLen & 0xff));
  if(hashInfo.littleEndian)
    bitLenStr = reverse(bitLenStr);

  var newData = data + '\x80' + '\x00'.repeat(paddingLen - 1 + (hashInfo.bitLenSize - 8)) + bitLenStr + appendText;

  return { newData: newData, newSignature: newSignature };
}

var lastStr = '', lastBytes = Array(), lastExcept;

try {
  var navigationParts = location.hash.substr(1).split('/');
  var pageName = navigationParts[0];
  if(pageName == 'conv')
    lastStr = urldecode(navigationParts[1] || "");
  else if(pageName == 'hash')
    $('#tabHash').tab('show');
  else if(pageName == 'rsa')
    $('#tabRSA').tab('show');
  else if(pageName == 'upc')
    $('#tabUPC').tab('show');
} catch(err){ }

function readBlob(blob){
    return new Promise(function(resolve, reject){
        var reader = new FileReader();
        reader.onload = function() {
            resolve(reader.result);
        };
        reader.onerror = function(e) {
            reject(e);
        };
        reader.readAsBinaryString(blob);
    });
}

function keyEventSignup(item, func){
    item.keypress(func);
    item.keyup(func);
}

$(function(){
  for(var i = 1; i <= 25; i++)
    $('#rotArea').append('<p>\
                <input type="text" id="rot'+i+'" placeholder="ROT-'+i+'" class="form-control input-sm" />\
                <span class="label label-'+(i==13 ? 'danger' : 'primary')+' inputLabel">ROT'+i+'</span>\
            </p>');

  var inpAscii = $('#inpAscii'), inpHex = $('#inpHex'), inpOct = $('#inpOct'), inpDec = $('#inpDec'), inpBase64 = $('#inpBase64'), inpBase32 = $('#inpBase32'),
    inpUrlEnc = $('#inpUrlEnc'), inpHtmlEnc = $('#inpHtmlEnc'), inpBinary = $('#inpBinary'), inpReverse = $('#inpReverse'), inpMorse = $('#inpMorse'), inpInteger = $('#inpInteger'),
    md5 = $('#md5'), ripemd160 = $('#ripemd160'), sha1 = $('#sha1'), sha256 = $('#sha256'), sha512 = $('#sha512'), sha3 = $('#sha3'), dataLength = $('#dataLength'), dataLengthBits = $('#dataLengthBits'),
    lLowercase = $('#lLowercase'), lUppercase = $('#lUppercase'),
    showRot = $('#showRot'), showHash = $('#showHash'), showGeneral = $('#showGeneral'), showMisc = $('#showMisc'),
    inpHashOrigData = $('#hashOrigData'), inpHashOrigSign = $('#hashOrigSign'), inpHashSecretLen = $('#hashSecretLen'),
    inpHashAppendData = $('#hashAppendData'), inpHashNewData = $('#hashNewData'), inpHashNewSignature = $('#hashNewSignature'),
    txtHashAlgorithm = $('#txtHashAlgorithm');

  var showButtons = Array(showRot, showHash, showGeneral, showMisc);

  var inpRots = Array();
  for(var i = 1; i <= 25; i++)
    inpRots[i] = $('#rot' + i);

  $('#btnDownload').click(function(){
    var a = document.createElement("a");
    document.body.appendChild(a);
    a.style = "display:none";
    var blob = new Blob([new Uint8Array(lastBytes)], {type: "octet/stream"});
    var url = window.URL.createObjectURL(blob);
    a.href = url;
    a.download = 'data.txt';
    a.click();
    window.URL.revokeObjectURL(url);
  });
  
  var fileInput = $('#fileInput');
  
  $('#btnUpload').click(function(){ fileInput.click(); });
  
  fileInput.on('change', function(){
      readBlob(fileInput.get(0).files[0]).then(function(fileContent){ convRefreshAll(fileContent); });
  });

  $('#btnReverse').click(function(){
    convRefreshAll(reverse(lastStr));
  });

  $('#mainTabs a').on('shown.bs.tab', function (e) {
    if(e.target.id == 'tabAscii')
      convRefreshToLast();
    else if(e.target.id == 'tabHash')
      refreshHash();
    else if(e.target.id == 'tabRSA')
      window.location.hash = "rsa";
    else if(e.target.id == 'tabUPC')
      window.location.hash = "upc";
  });
  
  var dragLeaveClear;
  var body = $("body");
  var fileDropShadow = $("#fileDropShadow");
  body.on("dragover", function(event) {
    event.preventDefault();  
    event.stopPropagation();
    
    if(dragLeaveClear){ clearTimeout(dragLeaveClear); dragLeaveClear = null; }
    
    fileDropShadow.show();
  });
  
  body.on("dragleave", function(event) {
    event.preventDefault();
    event.stopPropagation();

    if(dragLeaveClear)
        clearTimeout(dragLeaveClear);
    
    dragLeaveClear = setTimeout(function(){ fileDropShadow.hide(); }, 100);
  });
  
  body.on("drop", function(event) {
    event.preventDefault();  
    event.stopPropagation();
    fileDropShadow.hide();
    readBlob(event.originalEvent.dataTransfer.files[0]).then(function(fileContent){ convRefreshAll(fileContent); });
  });
  
  function morseStyle(){ inpMorse.toggleClass('morseContent', inpMorse.val() != ''); }

  keyEventSignup(inpMorse, morseStyle);

  $("#showButtons label").click(function(e){ setTimeout(function(){
    localStorage.setItem($(e.target).attr('id') + '.active', $(e.target).hasClass('active'));
    convRefreshToLast();
  }, 0); });

  for(var i = 0; i < showButtons.length; i++){
    var isActive = localStorage.getItem(showButtons[i].attr('id') + '.active');
    if(isActive === null) continue;
    isActive = isActive === "true";

    showButtons[i].toggleClass('active', isActive);
    $(showButtons[i].attr('data-target')).toggleClass('in', isActive).toggleClass('collapse', !isActive);
  }

  var historyDisabled = false;
  function convRefreshAll(bytesOrStr, except, force){
    //var start = new Date().getTime();

    var isStr = $.type(bytesOrStr) === "string";
    var str = isStr ? bytesOrStr : bytesToStr(bytesOrStr);
    var bytes = !isStr ? bytesOrStr : strToBytes(bytesOrStr);

    if(str == lastStr && !force)
      return;

    lastStr = str;
    lastBytes = bytes;
    lastExcept = except;

    dataLength.text(str.length);
    dataLengthBits.text(str.length * 8);

    if(except != inpAscii) inpAscii.val(str);

    if(!historyDisabled && history.replaceState && $("#tabAscii").parent().hasClass('active'))
    {
        try
        {
            history.replaceState(null, null, '#conv/' + urlencode(str)); 
        } catch(e)
        {
            console.log('history.replaceState failed: ' + e);
            historyDisabled = true;
        }
    }

    if(showGeneral.hasClass('active')){
      if(except != inpDec) inpDec.val(bytesToDecList(bytes));
      if(except != inpHex) inpHex.val(bytesToHex(bytes, ' '));
      if(except != inpOct) inpOct.val(bytesToOct(bytes, ' '));
      if(except != inpBase64) inpBase64.val(bytesToBase64(bytes));
      if(except != inpBase32) inpBase32.val(bytesToBase32(bytes));
      if(except != inpUrlEnc) inpUrlEnc.val(urlencode(str));
      if(except != inpHtmlEnc) inpHtmlEnc.val(htmlEncode(str));
      if(except != inpBinary) inpBinary.val(bytesToBinary(bytes));
      if(except != inpInteger) inpInteger.val(bytesToIntStr(bytes));
    }

    if(showMisc.hasClass('active')) {
      if (except != inpReverse) inpReverse.val(reverse(str));
      if (except != inpMorse) inpMorse.val(morseEncode(str));
      lLowercase.val(str.toLowerCase());
      lUppercase.val(str.toUpperCase());
      morseStyle();
    }

    if(showRot.hasClass('active'))
      for(var i = 1; i <= 25; i++)
        if(except != inpRots[i])
          inpRots[i].val(rot(str,i));

    if(showHash.hasClass('active')){
      var wordArray = CryptoJS.enc.Latin1.parse(str);
      md5.val(CryptoJS.MD5(wordArray));
      ripemd160.val(CryptoJS.RIPEMD160(wordArray));
      sha1.val(CryptoJS.SHA1(wordArray));
      sha256.val(CryptoJS.SHA256(wordArray));
      sha512.val(CryptoJS.SHA512(wordArray));
      sha3.val(CryptoJS.SHA3(wordArray));
    }
    
    //console.log('refreshAll: ' + (new Date().getTime() - start) + 'ms -> ' + str);
  }

  function convRefreshToLast(){ convRefreshAll(lastStr, lastExcept, true); }

  convRefreshToLast();

  RegExp.prototype.matches = function(str){
    var matches = [];
    var match;
    while(match = this.exec(str))
      matches.push(match[0]);
    return matches;
  };

  function inputByteHandle(input, toByteConv, funcToCall){
    keyEventSignup(input, function(){
      var inputVal = input.val();
      try {
        var bytes = toByteConv(inputVal);
        input.parent().removeClass('has-error');
      } catch(err) {
        input.parent().addClass('has-error');
      }
      funcToCall(bytes, input);
    });
  }

  function convInputByteHandle(input, toByteConv){
    inputByteHandle(input, toByteConv, convRefreshAll);
  }

  convInputByteHandle(inpAscii, strToBytes);
  convInputByteHandle(inpDec, decListToBytes);
  convInputByteHandle(inpHex, hexToBytes);
  convInputByteHandle(inpOct, octToBytes);
  convInputByteHandle(inpBase64, base64ToBytes);
  convInputByteHandle(inpBase32, base32ToBytes);
  convInputByteHandle(inpUrlEnc, urldecode);
  convInputByteHandle(inpHtmlEnc, htmlDecode);
  convInputByteHandle(inpBinary, binaryToBytes);
  convInputByteHandle(inpReverse, reverse);
  convInputByteHandle(inpMorse, morseDecode);
  convInputByteHandle(inpInteger, intStrToBytes);
  for(var i = 1; i <= 25; i++)
    convInputByteHandle(inpRots[i], function(i){ return function(str){ return rot(str, -i); }; }(i));

  function detectFormat(text){
    var onlyDigits = !!/^[0-9]+$/.exec(text);
    var onlyHex = !!/^[0-9a-fA-F ]+$/.exec(text);
    var onlyB64 = !!/^[0-9a-zA-Z+=/]+$/.exec(text);
//            var hasLowerAlpha = !!/[a-z]/.exec(text);
//            var hasUpperAlpha = !!/[A-Z]/.exec(text);
    var hasB64specChar = !!/[/+=]/.exec(text);
    var containsSpace = !!/ /.exec(text);

    var format = 'ascii';
    if(onlyDigits && containsSpace)
      format = 'dec';
    else if(onlyHex)
      format = 'hex';
    else if(onlyB64 && !containsSpace && hasB64specChar){
      try { atob(text); format = 'b64'; } catch(e) { }
    }

    console.log('detectFormat', format, { text: text, onlyDigits: onlyDigits, onlyHex: onlyHex, onlyB64: onlyB64, containsSpace: containsSpace });

    return format;
  }

  function formatInputGet(input){
    var component = input.closest('.formatSelector');
    var format = component.find('.selVal').text();
    var formattedValue = input.val();

    var isAutoFormat = format == 'auto';
    if(isAutoFormat)
      format = detectFormat(formattedValue);

    var inputLabel = component.find('.inputLabel');
    inputLabel.css('display', isAutoFormat ? 'block' : 'none');
    inputLabel.text(format.toUpperCase());
    inputLabel.toggleClass('label-primary', format == 'ascii');
    inputLabel.toggleClass('label-danger', format == 'hex');
    inputLabel.toggleClass('label-success', format == 'b64');
    inputLabel.toggleClass('label-info', format == 'dec');

    var plainValue;
    if(format == 'hex')
      plainValue = bytesToStr(hexToBytes(formattedValue));
    else if(format == 'b64')
      plainValue = base64ToStr(formattedValue);
    else if(format == 'b32')
      plainValue = base32ToStr(formattedValue);
    else if(format == 'dec')
      plainValue = bytesToStr(decListToBytes(formattedValue));
    else if(format == 'int')
      plainValue = bytesToStr(intStrToBytes(formattedValue));
    else
      plainValue = formattedValue;

    return plainValue;
  }

  function formatInputSet(input, newValue){
    var format = input.closest('.formatSelector').find('.selVal').text();

    var formattedValue;
    if(format == 'hex')
      formattedValue = bytesToHex(strToBytes(newValue));
    else if(format == 'b64')
      formattedValue = strToBase64(newValue);
    else if(format == 'b32')
      formattedValue = strToBase32(newValue);
    else if(format == 'dec')
      formattedValue = bytesToDecList(strToBytes(newValue));
    else
      formattedValue = newValue;

    input.val(formattedValue);
  }

  function refreshHash(){
    var origData = formatInputGet(inpHashOrigData);
    var origSign = formatInputGet(inpHashOrigSign);
    var secretLen = parseInt(inpHashSecretLen.val());
    var appendData = formatInputGet(inpHashAppendData);

    var hashInfoName =
      origSign.length == hashInfos.md5.hashLen ? 'md5' :
        origSign.length == hashInfos.sha1.hashLen ? 'sha1' :
          origSign.length == hashInfos.sha256.hashLen ? 'sha256' :
            origSign.length == hashInfos.sha512.hashLen ? 'sha512' : null;

    txtHashAlgorithm.text(hashInfoName ? hashInfoName.toUpperCase() : "Could not detect hash type!");

    var result = hashInfoName ? lengthExtensionAttack(hashInfos[hashInfoName], origData, origSign, secretLen, appendData) : { newSignature: "", newData: "" };

    formatInputSet(inpHashNewSignature, result.newSignature);
    formatInputSet(inpHashNewData, result.newData);

    if(history.replaceState && $("#tabHash").parent().hasClass('active'))
      history.replaceState(null, null, '#hash/' + urlencode(origData) + "/" + strToHex(origSign) +
        "/" + urlencode(secretLen || 0) + "/" + urlencode(appendData));
  }

  new Array(inpHashOrigData, inpHashOrigSign, inpHashSecretLen, inpHashAppendData).forEach(function(x){ keyEventSignup(x, refreshHash); });

  $('.formatSelector a').click(function(e){
    var a = $(e.target);
    a.closest('.formatSelector').find('.selVal').text(a.text());
    refreshHash();
  });

  if(pageName == 'hash'){
    if(navigationParts.length > 1) inpHashOrigData.val(urldecode(navigationParts[1]));
    if(navigationParts.length > 2) inpHashOrigSign.val(navigationParts[2]);
    if(navigationParts.length > 3) inpHashSecretLen.val(urldecode(navigationParts[3]));
    if(navigationParts.length > 4) inpHashAppendData.val(urldecode(navigationParts[4]));
  }

  refreshHash();
//        console.log('lengthExtensionAttack MD5', lengthExtensionAttack(hashInfos.md5, 'hello', '11e2d168019acd14ecdb5ec80a98bb38', 6, 'bello'));
//        console.log('lengthExtensionAttack SHA1', lengthExtensionAttack(hashInfos.sha1, 'hello', 'a590ccecb687967079362e49b7fe6c5258d09be5', 6, 'bello'));
//        console.log('lengthExtensionAttack SHA256', lengthExtensionAttack(hashInfos.sha256, 'hello', '1d4d234df92246e120bc62a10d8751882494a8a9bae09c494a519a783a128732', 6, 'bello'));
//        console.log('lengthExtensionAttack SHA512', lengthExtensionAttack(hashInfos.sha512, 'hello', 'adee6c2ae315a8dedd04462b8ed40221f699f521d5c74feac968e6efb96513d9f6f9aa6ce4b52fec3bd3816340610fab8f182b57fd9bbd53a431dfc87fd6a5e7', 6, 'bello'));
//        console.log('lengthExtensionAttack RIPEMD160', lengthExtensionAttack(hashInfos.ripemd160, 'hello', 'eeaf34a1c3687ea7082a38a6eb45c6ea19080251', 6, 'bello'));
});
