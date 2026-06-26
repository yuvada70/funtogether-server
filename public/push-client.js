function urlBase64ToUint8Array(base64String) {
  var padding = "=".repeat((4 - base64String.length % 4) % 4);
  var base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  var rawData = window.atob(base64);
  var outputArray = new Uint8Array(rawData.length);
  for (var i = 0; i < rawData.length; i++) outputArray[i] = rawData.charCodeAt(i);
  return outputArray;
}

async function subscribeToPush(apiBase, token) {
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
    console.warn("Push not supported in this browser");
    return;
  }
  var permission = await Notification.requestPermission();
  if (permission !== "granted") {
    console.warn("Notification permission not granted");
    return;
  }
  var registration = await navigator.serviceWorker.register("/sw.js");

  var keyRes = await fetch(apiBase + "/api/push/vapid-public-key");
  if (!keyRes.ok) { console.warn("Push not configured on server"); return; }
  var keyData = await keyRes.json();

  var subscription = await registration.pushManager.getSubscription();
  if (!subscription) {
    subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(keyData.publicKey)
    });
  }

  await fetch(apiBase + "/api/push/subscribe", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify({ subscription: subscription.toJSON() })
  });
}

async function unsubscribeFromPush(apiBase, token) {
  if (!("serviceWorker" in navigator)) return;
  var registration = await navigator.serviceWorker.getRegistration("/sw.js");
  if (!registration) return;
  var subscription = await registration.pushManager.getSubscription();
  if (!subscription) return;
  await fetch(apiBase + "/api/push/unsubscribe", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify({ endpoint: subscription.endpoint })
  });
  await subscription.unsubscribe();
}
