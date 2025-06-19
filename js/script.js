// API Constants (keep them here as you provided them)
export const API_URL = "https://web-production-dd021.up.railway.app";
export const API_KEY = "-VXtL8dKjEQlj_ND9PGTPJxYvA1WYZpJUbfVWCNNoa8";

// --- Helper Functions for API Calls (Based on your backend/externalApi.jsw) ---

// Updated to send only email and API_KEY, matching your Wix backend's registerExternalUser
async function registerUserWithExternalDb(email) {
    const response = await fetch(`${API_URL}/auth/register`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            email: email,
            api_key: API_KEY // Included API_KEY in body as per your Wix backend example
        })
    });
    return response; // Return the full response to check .ok status
}

// This function remains largely the same, as login typically requires email and password
async function loginUserWithExternalDb(email, password) {
    const response = await fetch(`${API_URL}/auth/login`, { // Assuming /auth/login as a common endpoint
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            email: email,
            password: password,
        })
    });
    return response;
}


// This maps to your getExternalTokens, assuming a /auth/token endpoint if it's separate from login
// Often, login returns tokens directly, simplifying the flow.
async function getTokensFromExternalDb(email) {
    const response = await fetch(`${API_URL}/auth/token`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            // 'Authorization': `Bearer ${API_KEY}` // Consider if this endpoint needs a global API key or specific auth
        },
        body: JSON.stringify({
            email: email,
            // api_key: API_KEY // Only include if your /auth/token endpoint requires this client-side
        })
    });
    return response; // Returns the full response
}

// Function to store tokens (uses standard localStorage)
function storeTokens(accessToken, refreshToken) {
    localStorage.setItem("access_token", accessToken);
    localStorage.setItem("refresh_token", refreshToken);
    console.log("Tokens stored in localStorage.");
}

// Function to remove tokens on logout
function clearTokens() {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    console.log("Tokens cleared from localStorage.");
}

// Function to check if a user is "logged in" based on token presence
function isLoggedIn() {
    return localStorage.getItem("access_token") !== null;
}

document.addEventListener('DOMContentLoaded', () => {
    // --- Common Elements (Header/Footer - dynamic behavior) ---
    const loginLink = document.querySelector('a[href="login.html"]');
    const signupLink = document.querySelector('a[href="signup.html"]');
    // You might want to add a visible logout link in your header HTML like:
    // <a href="#" id="logout-link" style="display: none;">Logout</a>
    const logoutLink = document.getElementById('logout-link');

    // Update header links based on login status
    if (loginLink && signupLink) { // Ensure these elements exist before trying to manipulate
        if (isLoggedIn()) {
            loginLink.style.display = 'none';
            signupLink.style.display = 'none';
            if (logoutLink) logoutLink.style.display = 'block'; // Show logout if logged in
        } else {
            loginLink.style.display = 'block';
            signupLink.style.display = 'block';
            if (logoutLink) logoutLink.style.display = 'none'; // Hide logout if not logged in
        }
    }


    // Logout functionality
    if (logoutLink) {
        logoutLink.addEventListener('click', async (e) => {
            e.preventDefault();
            const refreshToken = localStorage.getItem("refresh_token");

            if (refreshToken) {
                try {
                    // Call API to invalidate refresh token if your backend supports it
                    // Assuming /auth/logout endpoint expects refresh_token in body
                    const response = await fetch(`${API_URL}/auth/logout`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ refresh_token: refreshToken })
                    });

                    if (response.ok) {
                        console.log("Backend logout successful.");
                    } else {
                        const errorData = await response.json();
                        console.error("Backend logout failed:", errorData.message || response.statusText);
                    }
                } catch (error) {
                    console.error("Error during logout API call:", error);
                }
            }

            clearTokens(); // Clear local storage regardless of API success
            alert('You have been logged out.');
            window.location.href = 'index.html'; // Redirect to home or login page
        });
    }

    // --- Generat Page Logic ---
    const generateBtn = document.getElementById('generate-btn');
    const downloadBtn = document.getElementById('download-btn');
    const stringsInput = document.getElementById('strings-input');
    const datesInput = document.getElementById('dates-input');
    const numbersInput = document.getElementById('numbers-input');
    const includeUppercaseCheckbox = document.getElementById('include-uppercase');
    const includeSymbolsCheckbox = document.getElementById('include-symbols');
    const passwordCountInput = document.getElementById('password-count');
    const minLengthRange = document.getElementById('password-length-range-min');
    const maxLengthRange = document.getElementById('password-length-range-max');
    const minLengthDisplay = document.getElementById('min-length-display');
    const maxLengthDisplay = document.getElementById('max-length-display');
    const passwordListDiv = document.getElementById('password-list');

    if (generateBtn) { // Check if elements exist (only on generate.html)
        // Redirect if not logged in to use generation
        if (!isLoggedIn()) {
            passwordListDiv.innerHTML = '<p class="no-passwords-msg" style="color: yellow;">Please log in to generate passwords.</p>';
            generateBtn.disabled = true;
            generateBtn.style.opacity = 0.5;
            // Optionally redirect to login: window.location.href = 'login.html';
        }

        // Update length range display
        minLengthRange.addEventListener('input', () => {
            let minVal = parseInt(minLengthRange.value);
            let maxVal = parseInt(maxLengthRange.value);
            if (minVal > maxVal) {
                maxLengthRange.value = minVal;
                maxVal = minVal;
            }
            minLengthDisplay.textContent = minVal;
            maxLengthDisplay.textContent = maxVal;
        });

        maxLengthRange.addEventListener('input', () => {
            let minVal = parseInt(minLengthRange.value);
            let maxVal = parseInt(maxLengthRange.value);
            if (maxVal < minVal) {
                minLengthRange.value = maxVal;
                minVal = maxVal;
            }
            minLengthDisplay.textContent = minVal;
            maxLengthDisplay.textContent = maxVal;
        });

        generateBtn.addEventListener('click', async () => {
            if (!isLoggedIn()) {
                alert('You must be logged in to generate passwords.');
                window.location.href = 'login.html';
                return;
            }

            passwordListDiv.innerHTML = '<p class="no-passwords-msg">Generating passwords...</p>';
            downloadBtn.style.display = 'none';

            const strings = stringsInput.value.split(',').map(s => s.trim()).filter(s => s.length > 0);
            const dates = datesInput.value.split(',').map(d => d.trim()).filter(d => d.length > 0);
            const numbers = numbersInput.value.split(',').map(n => n.trim()).filter(n => n.length > 0);
            const includeUppercase = includeUppercaseCheckbox.checked;
            const includeSymbols = includeSymbolsCheckbox.checked;
            const count = parseInt(passwordCountInput.value);
            const minLength = parseInt(minLengthRange.value);
            const maxLength = parseInt(maxLengthRange.value);

            if (strings.length === 0 && dates.length === 0 && numbers.length === 0) {
                passwordListDiv.innerHTML = '<p class="no-passwords-msg" style="color: yellow;">Please provide at least one string, date, or number.</p>';
                return;
            }
            if (isNaN(count) || count <= 0) {
                passwordListDiv.innerHTML = '<p class="no-passwords-msg" style="color: yellow;">Please enter a valid number of passwords to generate.</p>';
                return;
            }

            const payload = {
                strings: strings,
                dates: dates,
                numbers: numbers,
                includeUppercase: includeUppercase,
                includeSymbols: includeSymbols,
                minLength: minLength,
                maxLength: maxLength,
                count: count
            };

            try {
                const accessToken = localStorage.getItem("access_token");
                if (!accessToken) {
                    throw new Error("No access token found. Please log in.");
                }

                const response = await fetch(`${API_URL}/generate`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${accessToken}`
                    },
                    body: JSON.stringify(payload)
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    // Handle specific errors like token expiry here
                    if (response.status === 401 || response.status === 403) {
                         alert("Session expired or unauthorized. Please log in again.");
                         clearTokens();
                         window.location.href = 'login.html';
                         return;
                    }
                    throw new Error(`API error: ${errorData.message || response.statusText}`);
                }

                const result = await response.json();
                const generatedPasswords = result.passwords;

                if (generatedPasswords && generatedPasswords.length > 0) {
                    passwordListDiv.innerHTML = '';
                    generatedPasswords.slice(0, 100).forEach(password => {
                        const p = document.createElement('p');
                        p.textContent = password;
                        passwordListDiv.appendChild(p);
                    });

                    window.fullPasswordList = generatedPasswords;
                    downloadBtn.style.display = 'block';
                } else {
                    passwordListDiv.innerHTML = '<p class="no-passwords-msg">No passwords generated with the given criteria.</p>';
                }

            } catch (error) {
                console.error('Error generating passwords:', error);
                passwordListDiv.innerHTML = `<p class="no-passwords-msg" style="color: red;">Error: ${error.message}. Please check your input and try again.</p>`;
            }
        });

        if (downloadBtn) {
            downloadBtn.addEventListener('click', () => {
                if (window.fullPasswordList && window.fullPasswordList.length > 0) {
                    const blob = new Blob([window.fullPasswordList.join('\n')], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'darkhats_passwords.txt';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                }
            });
        }
    } // End of Generat Page Logic check

    // --- Login Page Logic ---
    const loginForm = document.getElementById('login-form');
    const loginEmailInput = document.getElementById('login-email');
    const loginPasswordInput = document.getElementById('login-password');
    const loginErrorMsg = document.getElementById('login-error-msg');
    const emailErrorIconLogin = document.querySelector('.error-icon[data-field="login-email"]');
    const passwordErrorIconLogin = document.querySelector('.error-icon[data-field="login-password"]');

    if (loginForm) { // Check if elements exist (only on login.html)
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // Reset error states
            loginErrorMsg.style.display = 'none';
            emailErrorIconLogin.style.display = 'none';
            passwordErrorIconLogin.style.display = 'none';

            const email = loginEmailInput.value.trim();
            const password = loginPasswordInput.value.trim();

            if (!email || !password) {
                loginErrorMsg.textContent = 'Please enter email and password';
                loginErrorMsg.style.display = 'block';
                if (!email) emailErrorIconLogin.style.display = 'inline-block';
                if (!password) passwordErrorIconLogin.style.display = 'inline-block';
                return;
            }

            try {
                // Step 1: Login to your external API
                const loginResponse = await loginUserWithExternalDb(email, password); // This will handle actual login and token return

                if (!loginResponse.ok) {
                    const errorData = await loginResponse.json();
                    throw new Error(`Login failed: ${errorData.message || loginResponse.statusText}`);
                }

                const loginData = await loginResponse.json();

                // Assuming your login endpoint directly returns access_token and refresh_token
                if (loginData.access_token && loginData.refresh_token) {
                    storeTokens(loginData.access_token, loginData.refresh_token);
                    alert('Login Successful!');
                    window.location.href = 'tools.html'; // Redirect to tools page or dashboard
                } else {
                    throw new Error("Failed to receive tokens after login.");
                }

            } catch (error) {
                console.error('Login error:', error);
                let displayMessage = error.message || 'An error occurred during login. Please try again.';
                // Common API error messages
                if (displayMessage.includes("Invalid credentials") || displayMessage.includes("Unauthorized")) {
                    displayMessage = "Invalid email or password.";
                }
                loginErrorMsg.textContent = displayMessage;
                loginErrorMsg.style.display = 'block';
                // Show error icons if appropriate
                if (displayMessage.includes("email")) emailErrorIconLogin.style.display = 'inline-block';
                if (displayMessage.includes("password")) passwordErrorIconLogin.style.display = 'inline-block';
            }
        });

        // Hide error icon on input
        loginEmailInput.addEventListener('input', () => { emailErrorIconLogin.style.display = 'none'; });
        loginPasswordInput.addEventListener('input', () => { passwordErrorIconLogin.style.display = 'none'; });

        // Event listener for "Forgot password?" link
        const forgotPasswordLink = document.querySelector('a[href="forgot-password.html"]');
        if (forgotPasswordLink) {
            forgotPasswordLink.addEventListener('click', (e) => {
                e.preventDefault(); // Prevent default link behavior
                // In a real app, you'd trigger a password reset flow here (e.g., prompt for email and send API request)
                alert('Forgot password functionality not yet implemented. Please contact support.');
                // window.location.href = 'forgot-password.html'; // If you create a dedicated page
            });
        }
    } // End of Login Page Logic check

    // --- Sign Up Page Logic ---
    const signupForm = document.getElementById('signup-form');
    const signupEmailInput = document.getElementById('signup-email');
    const signupPasswordInput = document.getElementById('signup-password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const agreeTermsCheckbox = document.getElementById('agree-terms');
    const signupErrorMsg = document.getElementById('signup-error-msg');

    const emailErrorIconSignup = document.querySelector('.error-icon[data-field="signup-email"]');
    const passwordErrorIconSignup = document.querySelector('.error-icon[data-field="signup-password"]');
    const confirmPasswordErrorIconSignup = document.querySelector('.error-icon[data-field="confirm-password"]');

    if (signupForm) { // Check if elements exist (only on signup.html)
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // Reset error states
            signupErrorMsg.style.display = 'none';
            emailErrorIconSignup.style.display = 'none';
            passwordErrorIconSignup.style.display = 'none';
            confirmPasswordErrorIconSignup.style.display = 'none';

            const email = signupEmailInput.value.trim();
            const password = signupPasswordInput.value.trim();
            const confirmPassword = confirmPasswordInput.value.trim();
            const agreeTerms = agreeTermsCheckbox.checked;

            let errors = [];

            if (!email) {
                errors.push('Email is required.');
                emailErrorIconSignup.style.display = 'inline-block';
            } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                errors.push('Please enter a valid email address.');
                emailErrorIconSignup.style.display = 'inline-block';
            }
            if (!password) {
                errors.push('Password is required.');
                passwordErrorIconSignup.style.display = 'inline-block';
            } else if (password.length < 8) { // Example: minimum password length
                errors.push('Password must be at least 8 characters long.');
                passwordErrorIconSignup.style.display = 'inline-block';
            }
            if (password !== confirmPassword) {
                errors.push('Passwords do not match.');
                confirmPasswordErrorIconSignup.style.display = 'inline-block';
            }
            if (!agreeTerms) {
                errors.push('You must agree to the terms and conditions.');
            }

            if (errors.length > 0) {
                signupErrorMsg.innerHTML = errors.map(msg => `• ${msg}`).join('<br>');
                signupErrorMsg.style.display = 'block';
                return;
            }

            try {
                // Step 1: Register user with your external API
                // This call now matches your Wix backend example for registerExternalUser
                const registerResponse = await registerUserWithExternalDb(email);

                if (!registerResponse.ok) {
                    const errorData = await registerResponse.json();
                    throw new Error(`Registration failed: ${errorData.message || registerResponse.statusText}`);
                }

                const registerData = await registerResponse.json();
                console.log('API Registration successful:', registerData);

                // Step 2: After successful registration, attempt to log in the user to get tokens
                // This step still needs email and password for the /auth/login endpoint
                const loginResponse = await loginUserWithExternalDb(email, password);

                if (!loginResponse.ok) {
                    const errorData = await loginResponse.json();
                    throw new Error(`Auto-login failed after registration: ${errorData.message || loginResponse.statusText}`);
                }

                const loginData = await loginResponse.json();
                if (loginData.access_token && loginData.refresh_token) {
                    storeTokens(loginData.access_token, loginData.refresh_token);
                    alert('Registration successful! You are now logged in.');
                    window.location.href = 'tools.html'; // Redirect to a protected page
                } else {
                    throw new Error("Failed to receive tokens after registration and auto-login.");
                }

            } catch (error) {
                console.error('Sign up error:', error);
                let displayMessage = error.message || 'An error occurred during registration. Please try again later.';
                if (displayMessage.includes("exists")) {
                    displayMessage = "An account with this email already exists.";
                }
                signupErrorMsg.innerHTML = displayMessage;
                signupErrorMsg.style.display = 'block';
            }
        });

        // Hide error icons on input
        signupEmailInput.addEventListener('input', () => { emailErrorIconSignup.style.display = 'none'; });
        signupPasswordInput.addEventListener('input', () => { passwordErrorIconSignup.style.display = 'none'; });
        confirmPasswordInput.addEventListener('input', () => { confirmPasswordErrorIconSignup.style.display = 'none'; });
        agreeTermsCheckbox.addEventListener('change', () => {
            // Remove 'You must agree' error if checked
            if (agreeTermsCheckbox.checked) {
                if (signupErrorMsg.textContent.includes('You must agree to the terms and conditions.')) {
                    let currentErrors = signupErrorMsg.innerHTML.split('<br>').filter(msg => !msg.includes('You must agree to the terms and conditions.'));
                    if (currentErrors.length === 0) {
                        signupErrorMsg.style.display = 'none';
                    } else {
                        signupErrorMsg.innerHTML = currentErrors.join('<br>');
                    }
                }
            }
        });
    } // End of Sign Up Page Logic check

    // Optional: Dynamic input fields for generate page (Add button)
    const addInputBtns = document.querySelectorAll('.input-group .add-input-btn');
    addInputBtns.forEach(button => {
        button.addEventListener('click', () => {
            const parentGroup = button.closest('.input-group');
            const originalInput = parentGroup.querySelector('input');
            const newInput = originalInput.cloneNode(true);
            newInput.value = ''; // Clear cloned input
            originalInput.parentNode.insertBefore(newInput, button);
            // Optionally add a remove button next to new inputs
        });
    });

});
