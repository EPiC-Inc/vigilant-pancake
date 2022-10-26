x = new Int16Array(1);
window.crypto.getRandomValues(x);
x = 15//x[0];

lock = new WebSocket("ws://"+window.location.host+"/gen_key");
lock.onmessage = (evt) => {
    // receive paint
    data = JSON.parse(evt.data)
    if (data.mix) {
        x = data.mix ** x;
        x %= data.prime;
        console.log("final: "+x);


        ws = new WebSocket("ws://"+window.location.host+"/echo");
        ws.onmessage = (evt) => {
            message = "<div class='msg'>"+evt.data+"</div>";
            document.getElementById('messages').innerHTML += message;
        };
        lock.close();
    } else {
        console.log(data.prime)
        mix = data.base ** x;
        console.log(mix)
        mix %= data.prime;
        console.log(mix)
        lock.send(mix)
    }

};

function sendMessage() {
    // decode with x
    var msg = document.getElementById('msgbox').value;
    if (msg) {
        ws.send(msg);
    }
    document.getElementById('msgbox').value = '';
}