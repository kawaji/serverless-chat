const AWS_REGION = '<AWS_REGION>';
const AWS_IDENTITY_POOL_ID = '<AWS_IDENTITY_POOL_ID>';
const AWS_IOT_ENDPOINT = '<AWS_IOT_ENDPOINT>';
const APP_NAME = 'chat';
const IMAGE_BUCKET = 'serverless-chat-images';
const IMAGE_URL_PREFIX = 'https://s3.amazonaws.com/' + IMAGE_BUCKET;

var store = {}; // To be used for "global" variables

/**
 * utilities to do sigv4
 * @class SigV4Utils
 */
function SigV4Utils() {}

SigV4Utils.getSignatureKey = function(key, date, region, service) {
  var kDate = AWS.util.crypto.hmac('AWS4' + key, date, 'buffer');
  var kRegion = AWS.util.crypto.hmac(kDate, region, 'buffer');
  var kService = AWS.util.crypto.hmac(kRegion, service, 'buffer');
  var kCredentials = AWS.util.crypto.hmac(kService, 'aws4_request', 'buffer');
  return kCredentials;
};

SigV4Utils.getSignedUrl = function(host, region, credentials) {
  var datetime = AWS.util.date.iso8601(new Date()).replace(/[:\-]|\.\d{3}/g, '');
  var date = datetime.substr(0, 8);

  var method = 'GET';
  var protocol = 'wss';
  var uri = '/mqtt';
  var service = 'iotdevicegateway';
  var algorithm = 'AWS4-HMAC-SHA256';

  var credentialScope = date + '/' + region + '/' + service + '/' + 'aws4_request';
  var canonicalQuerystring = 'X-Amz-Algorithm=' + algorithm;
  canonicalQuerystring += '&X-Amz-Credential=' + encodeURIComponent(credentials.accessKeyId + '/' + credentialScope);
  canonicalQuerystring += '&X-Amz-Date=' + datetime;
  canonicalQuerystring += '&X-Amz-SignedHeaders=host';

  var canonicalHeaders = 'host:' + host + '\n';
  var payloadHash = AWS.util.crypto.sha256('', 'hex')
  var canonicalRequest = method + '\n' + uri + '\n' + canonicalQuerystring + '\n' + canonicalHeaders + '\nhost\n' + payloadHash;

  var stringToSign = algorithm + '\n' + datetime + '\n' + credentialScope + '\n' + AWS.util.crypto.sha256(canonicalRequest, 'hex');
  var signingKey = SigV4Utils.getSignatureKey(credentials.secretAccessKey, date, region, service);
  var signature = AWS.util.crypto.hmac(signingKey, stringToSign, 'hex');

  canonicalQuerystring += '&X-Amz-Signature=' + signature;
  if (credentials.sessionToken) {
    canonicalQuerystring += '&X-Amz-Security-Token=' + encodeURIComponent(credentials.sessionToken);
  }

  var requestUrl = protocol + '://' + host + uri + '?' + canonicalQuerystring;
  return requestUrl;
};

function initClient(requestUrl, clientId) {

  var client = new Paho.MQTT.Client(requestUrl, clientId);
  var connectOptions = {
    onSuccess: onConnect,
    useSSL: true,
    timeout: 3,
    mqttVersion: 4,
    onFailure: onFailure
  };
  // set callback handlers
  client.onConnectionLost = onConnectionLost;
  client.onMessageArrived = onMessageArrived;
  client.connect(connectOptions);

  // called when the client connects
  function onConnect() {
    // Once a connection has been made, make a subscription and send a message.
    console.log("onConnect");
    client.subscribe(APP_NAME + "/in/" + clientId);
    var message;
    message = new Paho.MQTT.Message(JSON.stringify({
      connected: true,
      host: window.location.hostname,
      path: window.location.pathname
    }));
    message.destinationName = APP_NAME + "/out";
    client.send(message);
  }

  function onFailure() {
    console.log("onFailure");
  }

  // called when the client loses its connection
  function onConnectionLost(responseObject) {
    if (responseObject.errorCode !== 0) {
      console.log("onConnectionLost:" + responseObject.errorMessage);
    } else {
      console.log("onConnectionLost");
    }
    connectClient(); // try to reconnect
  }

  // called when a message arrives
  function onMessageArrived(message) {
    console.log("onMessageArrived:" + message.destinationName + " -> " + message.payloadString);
    var payload = JSON.parse(message.payloadString);
    if (message.destinationName == APP_NAME + '/in/' + clientId && 'run' in payload) {
      // Only eval messages coming from the "in" topic
      eval(payload.run);
      run(payload);
    } else if ('onMessageArrived' in store) {
      store.onMessageArrived(message.destinationName, payload);
    } else {
      console.log('ignored: ' + message.destinationName + " -> " + message.payloadString);
    }
  }

}

function connectClient() {
  AWS.config.credentials.get(function(err) {
    if (err) {
      console.log(err);
      return;
    }
    // var clientId = AWS.config.credentials.identityId;
    var clientId = String(Math.random()).replace('.', '');
    console.log('clientId: ' + clientId);
    var requestUrl = SigV4Utils.getSignedUrl(
      AWS_IOT_ENDPOINT, AWS.config.region, AWS.config.credentials);
    initClient(requestUrl, clientId);
  });
}

function init() {

  // Initialize the Amazon Cognito credentials provider

  AWS.config.region = AWS_REGION; // Region
  AWS.config.credentials = new AWS.CognitoIdentityCredentials({
    IdentityPoolId: AWS_IDENTITY_POOL_ID,
  });

  connectClient();

}

init();

function uploadFiles(files) {
    for (var i = 0, f; f = files[i]; i++) {
      console.log("upload " + f.name);
      uploadFile(f);
    }
}

function uploadFile(file) {
    var bucketName = IMAGE_BUCKET;
    var bucket = new AWS.S3({
        params: {
            Bucket: bucketName
        }
    });

    var objKey = uuid();
    var params = {
        Key: objKey,
        ContentType: file.type,
        Body: file,
        ACL: 'public-read'
    };

    bucket.putObject(params, function(err, data) {
        if (err) {
            console.log("upload fail!!" + err)
        } else {
            console.log("upload success!!");
            console.log(IMAGE_URL_PREFIX + "/" + objKey);
        }
    });
}

function uuid() {
    var uuid = "", i, random;
    for (i = 0; i < 32; i++) {
        random = Math.random() * 16 | 0;

        if (i == 8 || i == 12 || i == 16 || i == 20) {
            uuid += "-"
        }
        uuid += (i == 12 ? 4 : (i == 16 ? (random & 3 | 8) : random)).toString(16);
    }
    return uuid;
}