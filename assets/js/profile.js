// Step 1: Add an event listener to the checkbox to toggle password visibility
document.getElementById('show-password').addEventListener('change', function() {
    const passwordField = document.getElementById('password');
    const confirmPasswordField = document.getElementById('confirm-password');
    // Toggle the type of the password fields based on the checkbox state
    if (this.checked) {
        passwordField.type = 'text'; // Show password
        confirmPasswordField.type = 'text'; // Show confirm password
    } else {
        passwordField.type = 'password'; // Hide password
        confirmPasswordField.type = 'password'; // Hide confirm password
    }
});
