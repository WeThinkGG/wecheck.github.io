document.addEventListener("DOMContentLoaded", () => {
    const validPaths = ["", "about", "resume", "portfolio"]; // Add all valid paths here

    // Check if the path is valid
    const path = window.location.pathname.split("/").pop();
    if (!validPaths.includes(path)) {
        // Redirect to a custom 404 page or display a 404 message
        document.body.innerHTML = `
            <div style="text-align:center; padding: 50px;">
                <h1>404 - Page Not Found</h1>
                <p>Sorry, the page you are looking for does not exist.</p>
                <a href="/">Go Back to Home</a>
            </div>`;
    }
});
