// RouterSploit GUI - Web Audio API Sound Generator
// Creates synthetic sound effects when audio files are not available

class SoundGenerator {
    constructor() {
        this.audioContext = null;
        this.sounds = {};
        this.init();
    }

    init() {
        // Initialize Web Audio API
        try {
            this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
        } catch (e) {
            console.warn('Web Audio API not supported');
            return;
        }

        // Generate synthetic sounds
        this.generateSounds();
    }

    generateSounds() {
        // Click sound - short beep
        this.sounds.click = () => this.createBeep(800, 0.1, 0.3);
        
        // Type sound - short tick
        this.sounds.type = () => this.createBeep(1200, 0.05, 0.1);
        
        // Success sound - ascending tone
        this.sounds.success = () => this.createAscendingTone(600, 900, 0.3, 0.5);
        
        // Error sound - descending harsh tone
        this.sounds.error = () => this.createDescendingTone(400, 200, 0.3, 0.6);
        
        // Startup sound - cyber boot sequence
        this.sounds.startup = () => this.createStartupSequence();
        
        // Scan sound - sweeping tone
        this.sounds.scan = () => this.createSweepTone(300, 1200, 1.0, 0.4);
    }

    createBeep(frequency, duration, volume = 0.3) {
        if (!this.audioContext) return;

        const oscillator = this.audioContext.createOscillator();
        const gainNode = this.audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(this.audioContext.destination);

        oscillator.frequency.value = frequency;
        oscillator.type = 'sine';

        gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
        gainNode.gain.linearRampToValueAtTime(volume, this.audioContext.currentTime + 0.01);
        gainNode.gain.exponentialRampToValueAtTime(0.001, this.audioContext.currentTime + duration);

        oscillator.start();
        oscillator.stop(this.audioContext.currentTime + duration);
    }

    createAscendingTone(startFreq, endFreq, duration, volume = 0.3) {
        if (!this.audioContext) return;

        const oscillator = this.audioContext.createOscillator();
        const gainNode = this.audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(this.audioContext.destination);

        oscillator.frequency.setValueAtTime(startFreq, this.audioContext.currentTime);
        oscillator.frequency.linearRampToValueAtTime(endFreq, this.audioContext.currentTime + duration);
        oscillator.type = 'square';

        gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
        gainNode.gain.linearRampToValueAtTime(volume, this.audioContext.currentTime + 0.01);
        gainNode.gain.exponentialRampToValueAtTime(0.001, this.audioContext.currentTime + duration);

        oscillator.start();
        oscillator.stop(this.audioContext.currentTime + duration);
    }

    createDescendingTone(startFreq, endFreq, duration, volume = 0.3) {
        if (!this.audioContext) return;

        const oscillator = this.audioContext.createOscillator();
        const gainNode = this.audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(this.audioContext.destination);

        oscillator.frequency.setValueAtTime(startFreq, this.audioContext.currentTime);
        oscillator.frequency.linearRampToValueAtTime(endFreq, this.audioContext.currentTime + duration);
        oscillator.type = 'sawtooth';

        gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
        gainNode.gain.linearRampToValueAtTime(volume, this.audioContext.currentTime + 0.01);
        gainNode.gain.exponentialRampToValueAtTime(0.001, this.audioContext.currentTime + duration);

        oscillator.start();
        oscillator.stop(this.audioContext.currentTime + duration);
    }

    createSweepTone(startFreq, endFreq, duration, volume = 0.3) {
        if (!this.audioContext) return;

        const oscillator = this.audioContext.createOscillator();
        const gainNode = this.audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(this.audioContext.destination);

        oscillator.frequency.setValueAtTime(startFreq, this.audioContext.currentTime);
        oscillator.frequency.exponentialRampToValueAtTime(endFreq, this.audioContext.currentTime + duration);
        oscillator.type = 'triangle';

        gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
        gainNode.gain.linearRampToValueAtTime(volume, this.audioContext.currentTime + 0.01);
        gainNode.gain.exponentialRampToValueAtTime(0.001, this.audioContext.currentTime + duration);

        oscillator.start();
        oscillator.stop(this.audioContext.currentTime + duration);
    }

    createStartupSequence() {
        if (!this.audioContext) return;

        // Create a sequence of beeps
        const frequencies = [400, 600, 800, 1000, 1200];
        frequencies.forEach((freq, index) => {
            setTimeout(() => {
                this.createBeep(freq, 0.1, 0.2);
            }, index * 100);
        });

        // Final sweep
        setTimeout(() => {
            this.createSweepTone(400, 1600, 0.5, 0.3);
        }, 600);
    }

    playSound(type) {
        if (this.sounds[type]) {
            this.sounds[type]();
        }
    }
}

// Create global sound generator instance
window.soundGenerator = new SoundGenerator();

// Override the effects manager sound loading to use synthetic sounds
document.addEventListener('DOMContentLoaded', () => {
    // Wait for effects manager to be initialized
    setTimeout(() => {
        if (window.effectsManager) {
            // Replace the sound loading with synthetic sounds
            const originalPlaySound = window.effectsManager.playSound;
            
            window.effectsManager.playSound = function(type) {
                if (this.soundEnabled) {
                    // Try to play the actual audio file first
                    if (this.sounds[type]) {
                        this.sounds[type].currentTime = 0;
                        this.sounds[type].play().catch(e => {
                            // Fallback to synthetic sound
                            window.soundGenerator.playSound(type);
                        });
                    } else {
                        // Use synthetic sound
                        window.soundGenerator.playSound(type);
                    }
                }
            };
        }
    }, 100);
}); 