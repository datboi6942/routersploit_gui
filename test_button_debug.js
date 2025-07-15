// Auto-Own Button Debug Test
// Run this in the browser console to debug the button functionality

function debugAutoOwnButton() {
    console.log("🔍 Starting Auto-Own Button Debug Test...");
    
    // Check if the button exists
    const startBtn = document.getElementById('startAutoOwnBtn');
    if (!startBtn) {
        console.error("❌ Start Auto-Own button not found!");
        return;
    }
    
    console.log("✅ Start Auto-Own button found:", startBtn);
    
    // Check button properties
    console.log("🔍 Button properties:");
    console.log("- Disabled:", startBtn.disabled);
    console.log("- Display style:", window.getComputedStyle(startBtn).display);
    console.log("- Visibility:", window.getComputedStyle(startBtn).visibility);
    console.log("- Pointer events:", window.getComputedStyle(startBtn).pointerEvents);
    
    // Check if target input exists
    const targetInput = document.getElementById('autoOwnTarget');
    if (!targetInput) {
        console.error("❌ Target input not found!");
        return;
    }
    
    console.log("✅ Target input found:", targetInput);
    
    // Check if verbose checkbox exists
    const verboseCheckbox = document.getElementById('autoOwnVerbose');
    console.log("🔍 Verbose checkbox:", verboseCheckbox ? "Found" : "Not found");
    
    // Check if debug checkbox exists
    const debugCheckbox = document.getElementById('autoOwnDebug');
    console.log("🔍 Debug checkbox:", debugCheckbox ? "Found" : "Not found");
    
    // Check event listeners
    console.log("🔍 Testing button click...");
    
    // Add a test target
    targetInput.value = "192.168.1.1";
    console.log("✅ Test target set:", targetInput.value);
    
    // Try to click the button
    try {
        startBtn.click();
        console.log("✅ Button clicked successfully");
    } catch (error) {
        console.error("❌ Error clicking button:", error);
    }
    
    // Check if RouterSploitApp exists
    if (typeof app !== 'undefined') {
        console.log("✅ RouterSploitApp instance found");
        
        // Check if startAutoOwn method exists
        if (typeof app.startAutoOwn === 'function') {
            console.log("✅ startAutoOwn method found");
        } else {
            console.error("❌ startAutoOwn method not found");
        }
    } else {
        console.error("❌ RouterSploitApp instance not found");
    }
    
    console.log("🏁 Auto-Own Button Debug Test completed");
}

// Run the debug test
debugAutoOwnButton();

// Also add a manual test function
function testAutoOwnManually() {
    console.log("🧪 Manual Auto-Own Test");
    
    const targetInput = document.getElementById('autoOwnTarget');
    if (targetInput) {
        targetInput.value = "192.168.1.1";
        console.log("✅ Target set to:", targetInput.value);
    }
    
    if (typeof app !== 'undefined' && typeof app.startAutoOwn === 'function') {
        console.log("🚀 Calling startAutoOwn method directly...");
        app.startAutoOwn();
    } else {
        console.error("❌ Cannot call startAutoOwn method");
    }
}

console.log("🎯 Debug functions loaded. Run testAutoOwnManually() to test manually."); 