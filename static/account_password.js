async function submitChange() {
    const err = document.getElementById("error");
    if (err) err.textContent = "";
    const current_password = document.getElementById("current_password")?.value || "";
    const new_password = document.getElementById("new_password")?.value || "";
    const new_password_confirm = document.getElementById("new_password_confirm")?.value || "";
    try {
        const res = await fetch("/api/auth/change-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ current_password, new_password, new_password_confirm }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            if (err) err.textContent = data.message || "Could not change password";
            return;
        }
        window.location.href = "/dashboard";
    } catch (e) {
        if (err) err.textContent = String(e);
    }
}
