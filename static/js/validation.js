function togglePassword(inputId, iconId) {
    const passwordInput = document.getElementById(inputId);
    const eyeIcon = document.getElementById(iconId);
    
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        eyeIcon.classList.remove("bi-eye");
        eyeIcon.classList.add("bi-eye-slash");
    } else {
        passwordInput.type = "password";
        eyeIcon.classList.remove("bi-eye-slash");
        eyeIcon.classList.add("bi-eye");
    }
}
function validatePassword() {
    const password = document.getElementById('password').value;
    const confirm = document.getElementById('confirm_password').value;
    const strengthBar = document.getElementById('strength-bar');
    const strengthText = document.getElementById('strength-text');
    const feedback = document.getElementById('password-feedback');
    const submitBtn = document.getElementById('submit-btn');

    // 1. Calculate Strength Score (Same as before)
    let strength = 0;
    if (password.length > 0) {
        if (password.length >= 8) strength += 25;
        if (/[A-Z]/.test(password)) strength += 25;
        if (/[0-9]/.test(password)) strength += 25;
        if (/[^A-Za-z0-9]/.test(password)) strength += 25;
    }

    // 2. Update Strength Meter Visuals
    strengthBar.style.width = strength + "%";
    if (strength === 0) {
        strengthText.innerHTML = "";
    } else if (strength <= 25) {
        strengthBar.className = "progress-bar bg-danger";
        strengthText.innerHTML = "Weak";
    } else if (strength <= 50) {
        strengthBar.className = "progress-bar bg-warning";
        strengthText.innerHTML = "Moderate";
    } else if (strength <= 75) {
        strengthBar.className = "progress-bar bg-info";
        strengthText.innerHTML = "Strong";
    } else {
        strengthBar.className = "progress-bar bg-success";
        strengthText.innerHTML = "Very Secure";
    }

    // 3. Independent Condition Checks
    const isLongEnough = password.length >= 8;
    const isMatching = (password === confirm);
    const isChangingPassword = password.length > 0;

    if (!isChangingPassword) {
        // Case: User is not changing password
        feedback.innerHTML = "";
        submitBtn.disabled = false;
    } else {
        // Case: User is typing a new password
        if (!isLongEnough) {
            feedback.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle"></i> Password must be at least 8 characters.</span>';
            submitBtn.disabled = true;
        } else if (confirm.length === 0) {
            feedback.innerHTML = '<span class="text-muted">Please confirm your new password.</span>';
            submitBtn.disabled = true;
        } else if (!isMatching) {
            feedback.innerHTML = '<span class="text-danger"><i class="bi bi-exclamation-triangle"></i> Passwords do not match.</span>';
            submitBtn.disabled = true;
        } else {
            // All conditions met
            feedback.innerHTML = '<span class="text-success"><i class="bi bi-check-circle-fill"></i> Ready to update!</span>';
            submitBtn.disabled = false;
        }
    }
}

/**
 * Validates the email format and updates the UI
 */
function validateEmail() {
    const emailInput = document.querySelector('input[type="email"]');
    if (!emailInput) return; // Exit if email field isn't on the current page

    const email = emailInput.value;
    const emailFeedback = document.getElementById('email-feedback');
    const submitBtn = document.getElementById('submit-btn');

    // Simple Regex for basic email format (name@domain.ext)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    // We only validate if there is text in the box
    if (email.length > 0) {
        if (emailRegex.test(email)) {
            emailInput.classList.remove('is-invalid');
            emailInput.classList.add('is-valid');
            if (emailFeedback) emailFeedback.innerHTML = "";
            submitBtn.disabled = false;
        } else {
            emailInput.classList.remove('is-valid');
            emailInput.classList.add('is-invalid');
            if (emailFeedback) {
                emailFeedback.innerHTML = '<span class="text-danger small">Please enter a valid email address.</span>';
            }
            submitBtn.disabled = true;
        }
    } else {
        // If empty, reset the styles
        emailInput.classList.remove('is-invalid', 'is-valid');
        if (emailFeedback) emailFeedback.innerHTML = "";
        submitBtn.disabled = false;
    }
}