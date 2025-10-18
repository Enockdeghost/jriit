// Meetings JavaScript Utilities

class MeetingManager {
    constructor() {
        this.socket = null;
        this.localStream = null;
        this.peerConnections = {};
        this.mediaConstraints = {
            video: { width: 1280, height: 720 },
            audio: true
        };
    }

    // Initialize meeting room
    async initializeMeeting(meetingId, userId) {
        try {
            await this.initializeMedia();
            this.initializeSocket(meetingId, userId);
            this.setupEventListeners();
        } catch (error) {
            console.error('Failed to initialize meeting:', error);
            this.showError('Failed to initialize meeting. Please refresh and try again.');
        }
    }

    // Initialize media devices
    async initializeMedia() {
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia(this.mediaConstraints);
            this.displayLocalVideo();
            return true;
        } catch (error) {
            console.error('Error accessing media devices:', error);
            
            // Try with lower constraints
            try {
                this.mediaConstraints.video = { width: 640, height: 480 };
                this.localStream = await navigator.mediaDevices.getUserMedia(this.mediaConstraints);
                this.displayLocalVideo();
                return true;
            } catch (fallbackError) {
                this.showError('Unable to access camera and microphone. Please check your permissions.');
                return false;
            }
        }
    }

    // Display local video stream
    displayLocalVideo() {
        const localVideo = document.getElementById('localVideo');
        if (localVideo && this.localStream) {
            localVideo.srcObject = this.localStream;
        }
    }

    // Initialize socket connection
    initializeSocket(meetingId, userId) {
        this.socket = io();
        
        this.socket.emit('join_meeting', {
            meeting_id: meetingId,
            user_id: userId
        });

        this.setupSocketListeners();
    }

    // Setup socket event listeners
    setupSocketListeners() {
        this.socket.on('connect', () => {
            console.log('Connected to meeting server');
        });

        this.socket.on('disconnect', () => {
            this.showError('Disconnected from meeting. Attempting to reconnect...');
        });

        this.socket.on('user_joined', (data) => {
            this.handleUserJoined(data);
        });

        this.socket.on('user_left', (data) => {
            this.handleUserLeft(data);
        });

        // Add other socket event listeners...
    }

    // Setup UI event listeners
    setupEventListeners() {
        // Media controls
        this.setupMediaControls();
        
        // UI controls
        this.setupUIControls();
        
        // Window events
        this.setupWindowEvents();
    }

    setupMediaControls() {
        const micToggle = document.getElementById('micToggle');
        const videoToggle = document.getElementById('videoToggle');
        const shareScreen = document.getElementById('shareScreen');
        const raiseHand = document.getElementById('raiseHand');

        if (micToggle) micToggle.addEventListener('click', () => this.toggleAudio());
        if (videoToggle) videoToggle.addEventListener('click', () => this.toggleVideo());
        if (shareScreen) shareScreen.addEventListener('click', () => this.toggleScreenShare());
        if (raiseHand) raiseHand.addEventListener('click', () => this.toggleHandRaise());
    }

    setupUIControls() {
        // Sidebar controls
        const sidebarToggle = document.getElementById('sidebarToggle');
        const sidebarTabs = document.querySelectorAll('.sidebar-tab');
        const leaveMeeting = document.getElementById('leaveMeeting');

        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => this.toggleSidebar());
        }

        if (sidebarTabs) {
            sidebarTabs.forEach(tab => {
                tab.addEventListener('click', (e) => {
                    const tabName = e.target.getAttribute('data-tab');
                    this.switchTab(tabName);
                });
            });
        }

        if (leaveMeeting) {
            leaveMeeting.addEventListener('click', () => this.showLeaveModal());
        }

        // Chat controls
        const chatSend = document.getElementById('chatSend');
        const chatInput = document.getElementById('chatInput');

        if (chatSend) chatSend.addEventListener('click', () => this.sendChatMessage());
        if (chatInput) {
            chatInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.sendChatMessage();
            });
        }
    }

    setupWindowEvents() {
        // Handle page refresh/close
        window.addEventListener('beforeunload', (e) => {
            if (this.socket) {
                this.socket.emit('leave_meeting');
            }
        });

        // Handle visibility change (tab switch)
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                // User switched tabs - could trigger proctoring alert
                console.log('User switched tabs');
            }
        });
    }

    // Media control methods
    toggleAudio() {
        if (!this.localStream) return;

        const audioTrack = this.localStream.getAudioTracks()[0];
        const enabled = !audioTrack.enabled;
        audioTrack.enabled = enabled;

        this.updateAudioUI(enabled);
        
        if (this.socket) {
            this.socket.emit('toggle_audio', {
                enabled: enabled
            });
        }
    }

    toggleVideo() {
        if (!this.localStream) return;

        const videoTrack = this.localStream.getVideoTracks()[0];
        const enabled = !videoTrack.enabled;
        videoTrack.enabled = enabled;

        this.updateVideoUI(enabled);
        
        if (this.socket) {
            this.socket.emit('toggle_video', {
                enabled: enabled
            });
        }
    }

    async toggleScreenShare() {
        try {
            const shareBtn = document.getElementById('shareScreen');
            const isSharing = shareBtn.classList.contains('active');

            if (!isSharing) {
                // Start sharing
                const screenStream = await navigator.mediaDevices.getDisplayMedia({
                    video: { cursor: 'always' },
                    audio: true
                });

                this.handleScreenShareStart(screenStream);
            } else {
                // Stop sharing
                this.handleScreenShareStop();
            }
        } catch (error) {
            console.error('Error sharing screen:', error);
            this.showError('Failed to share screen. Please try again.');
        }
    }

    toggleHandRaise() {
        const raiseHandBtn = document.getElementById('raiseHand');
        const raised = !raiseHandBtn.classList.contains('active');

        raiseHandBtn.classList.toggle('active', raised);
        raiseHandBtn.classList.toggle('hand-raised', raised);

        if (this.socket) {
            this.socket.emit('raise_hand', {
                raised: raised
            });
        }
    }

    // UI update methods
    updateAudioUI(enabled) {
        const micToggle = document.getElementById('micToggle');
        const localMicStatus = document.getElementById('localMicStatus');

        if (micToggle) {
            micToggle.innerHTML = enabled ? 
                '<i class="fas fa-microphone"></i>' : 
                '<i class="fas fa-microphone-slash"></i>';
        }

        if (localMicStatus) {
            localMicStatus.style.display = enabled ? 'none' : 'flex';
        }
    }

    updateVideoUI(enabled) {
        const videoToggle = document.getElementById('videoToggle');
        const localVideoStatus = document.getElementById('localVideoStatus');
        const localVideo = document.getElementById('localVideo');

        if (videoToggle) {
            videoToggle.innerHTML = enabled ? 
                '<i class="fas fa-video"></i>' : 
                '<i class="fas fa-video-slash"></i>';
        }

        if (localVideoStatus) {
            localVideoStatus.style.display = enabled ? 'none' : 'flex';
        }

        if (localVideo) {
            localVideo.style.display = enabled ? 'block' : 'none';
        }
    }

    handleScreenShareStart(screenStream) {
        const shareBtn = document.getElementById('shareScreen');
        shareBtn.classList.add('active');
        shareBtn.innerHTML = '<i class="fas fa-stop"></i>';

        // Replace video track in all peer connections
        const videoTrack = screenStream.getVideoTracks()[0];
        Object.values(this.peerConnections).forEach(pc => {
            const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video');
            if (sender) {
                sender.replaceTrack(videoTrack);
            }
        });

        // Update local video display
        const localVideo = document.getElementById('localVideo');
        localVideo.srcObject = screenStream;

        // Handle when screen share ends
        videoTrack.onended = () => {
            this.handleScreenShareStop();
        };

        this.screenStream = screenStream;
    }

    handleScreenShareStop() {
        const shareBtn = document.getElementById('shareScreen');
        shareBtn.classList.remove('active');
        shareBtn.innerHTML = '<i class="fas fa-desktop"></i>';

        // Restore camera stream
        if (this.localStream) {
            const videoTrack = this.localStream.getVideoTracks()[0];
            Object.values(this.peerConnections).forEach(pc => {
                const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video');
                if (sender) {
                    sender.replaceTrack(videoTrack);
                }
            });

            const localVideo = document.getElementById('localVideo');
            localVideo.srcObject = this.localStream;
        }

        // Stop screen stream
        if (this.screenStream) {
            this.screenStream.getTracks().forEach(track => track.stop());
            this.screenStream = null;
        }
    }

    // Navigation methods
    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        const toggleBtn = document.getElementById('sidebarToggle');

        if (sidebar && toggleBtn) {
            sidebar.classList.toggle('open');
            toggleBtn.innerHTML = sidebar.classList.contains('open') ? 
                '<i class="fas fa-chevron-right"></i>' : 
                '<i class="fas fa-chevron-left"></i>';
        }
    }

    switchTab(tabName) {
        // Update active tab
        document.querySelectorAll('.sidebar-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Show active content
        document.querySelectorAll('.sidebar-tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabName}Tab`).classList.add('active');
    }

    // Chat methods
    sendChatMessage() {
        const chatInput = document.getElementById('chatInput');
        const message = chatInput.value.trim();

        if (message && this.socket) {
            this.socket.emit('send_message', {
                message_text: message,
                message_type: 'public'
            });

            chatInput.value = '';
        }
    }

    // Utility methods
    showError(message) {
        // You can implement a toast notification system here
        console.error('Meeting Error:', message);
        
        // Simple alert for now - replace with proper notification system
        alert(`Error: ${message}`);
    }

    showSuccess(message) {
        console.log('Meeting Success:', message);
        // Implement success notification
    }

    // Cleanup method
    cleanup() {
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
        }

        if (this.screenStream) {
            this.screenStream.getTracks().forEach(track => track.stop());
        }

        Object.values(this.peerConnections).forEach(pc => pc.close());

        if (this.socket) {
            this.socket.disconnect();
        }
    }
}

// Global meeting manager instance
window.meetingManager = new MeetingManager();

// Utility functions
function formatTime(seconds) {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        console.log('Text copied to clipboard');
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { MeetingManager, formatTime, copyToClipboard };
}