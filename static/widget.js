const button = document.createElement("button");
button.textContent = "Visit Hostel Sampark";
button.style.cssText =
  "position:fixed;right:20px;bottom:20px;z-index:9999;padding:12px 16px;background:#4f46e5;color:white;border:0;border-radius:8px;cursor:pointer";

button.addEventListener("click", () => {
  window.open("https://hostel-sampark-app.onrender.com/", "_blank");
});

document.body.appendChild(button);