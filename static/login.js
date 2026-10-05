async function login() {
    const error = document.getElementById("error");
    if (error) error.textContent = "";
    const usernameEl = document.getElementById("username");
    const passwordEl = document.getElementById("password");
    const username = (usernameEl?.value || "").trim();
    const password = passwordEl?.value || "";

    try {
        const res = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });
        let data = {};
        try {
            data = await res.json();
        } catch {
            data = {};
        }
        if (!res.ok) {
            if (error) error.textContent = data.message || "Login failed.";
            return;
        }
        window.location.href = "/dashboard";
    } catch (e) {
        if (error) error.textContent = "Network error. Please try again.";
        console.error(e);
    }
}
