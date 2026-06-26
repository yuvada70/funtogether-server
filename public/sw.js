self.addEventListener("push", function(event) {
  var data = {};
  try { data = event.data.json(); } catch(e) { data = { title: "FunTogether", body: event.data ? event.data.text() : "" }; }
  event.waitUntil(
    self.registration.showNotification(data.title || "FunTogether", {
      body: data.body || "",
      icon: "/icon.png",
      badge: "/icon.png",
      data: { url: data.url || "/" }
    })
  );
});

self.addEventListener("notificationclick", function(event) {
  event.notification.close();
  var url = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(
    clients.matchAll({ type: "window" }).then(function(windowClients) {
      for (var i = 0; i < windowClients.length; i++) {
        if (windowClients[i].url.indexOf(url) !== -1) return windowClients[i].focus();
      }
      return clients.openWindow(url);
    })
  );
});
