/**
 * Secure Video Calling Client
 * Implements end-to-end encrypted video calls with DTLS-SRTP
 */

class SecureVideoCall {
    constructor(apiClient) {
        this.api = apiClient;
        this.peerConnection = null;
        this.localStream = null;
        this.remoteStream = null;
        this.ws = null;
        this.callId = null;
        this.isInitiator = false;
        
        // Security configuration
        this.config = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
                // Add TURN servers for production
            ],
            iceCandidatePoolSize: 10,
            bundlePolicy: 'max-bundle',
            rtcpMuxPolicy: 'require',
            iceTransportPolicy: 'all',  // Use 'relay' for maximum privacy
            sdpSemantics: 'unified-plan'
        };
        
        // Callbacks
        this.onLocalStream = null;
        this.onRemoteStream = null;
        this.onCallEnded = null;
        this.onError = null;
        this.onEncryptionVerified = null;
    }
    
    /**
     * Initialize WebSocket connection for signaling
     */
    async connectSignaling() {
        return new Promise((resolve, reject) => {
            try {
                this.ws = this.api.connectSignaling();
                
                this.ws.onopen = () => {
                    console.log('Signaling connected');
                };
                
                this.ws.onmessage = async (event) => {
                    const data = JSON.parse(event.data);
                    await this.handleSignalingMessage(data);
                };
                
                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    if (this.onError) this.onError(error);
                    reject(error);
                };
                
                this.ws.onclose = () => {
                    console.log('Signaling disconnected');
                    this.cleanup();
                };
                
                // Wait for connection confirmation
                const checkConnection = setInterval(() => {
                    if (this.ws.readyState === WebSocket.OPEN) {
                        clearInterval(checkConnection);
                        resolve();
                    }
                }, 100);
                
                setTimeout(() => {
                    clearInterval(checkConnection);
                    reject(new Error('WebSocket connection timeout'));
                }, 5000);
                
            } catch (error) {
                reject(error);
            }
        });
    }
    
    /**
     * Start a new call
     */
    async startCall(receiverId, callType = 'video') {
        try {
            // Connect signaling
            await this.connectSignaling();
            
            // Get local media
            await this.getLocalMedia(callType);
            
            // Initiate call via API
            const response = await this.api.initiateCall(receiverId, callType);
            this.callId = response.call_id;
            this.isInitiator = true;
            
            console.log('Call initiated:', response);
            console.log('Encryption:', response.encryption);
            
            // Create peer connection
            await this.createPeerConnection();
            
            // Create and send offer
            await this.createOffer();
            
            return response;
            
        } catch (error) {
            console.error('Failed to start call:', error);
            this.cleanup();
            throw error;
        }
    }
    
    /**
     * Answer incoming call
     */
    async answerCall(callId) {
        try {
            this.callId = callId;
            this.isInitiator = false;
            
            // Connect signaling
            await this.connectSignaling();
            
            // Accept call via API
            await this.api.respondToCall(callId, 'accept');
            
            // Get local media
            await this.getLocalMedia('video');
            
            // Create peer connection
            await this.createPeerConnection();
            
            console.log('Call answered');
            
        } catch (error) {
            console.error('Failed to answer call:', error);
            this.cleanup();
            throw error;
        }
    }
    
    /**
     * Reject incoming call
     */
    async rejectCall(callId) {
        try {
            await this.api.respondToCall(callId, 'reject');
            console.log('Call rejected');
        } catch (error) {
            console.error('Failed to reject call:', error);
            throw error;
        }
    }
    
    /**
     * End active call
     */
    async endCall() {
        try {
            if (this.callId) {
                await this.api.endCall(this.callId);
            }
            this.cleanup();
            if (this.onCallEnded) this.onCallEnded();
        } catch (error) {
            console.error('Failed to end call:', error);
            this.cleanup();
        }
    }
    
    /**
     * Get local media stream
     */
    async getLocalMedia(callType) {
        try {
            const constraints = {
                audio: true,
                video: callType === 'video' ? {
                    width: { ideal: 1280 },
                    height: { ideal: 720 },
                    frameRate: { ideal: 30 }
                } : false
            };
            
            this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
            
            if (this.onLocalStream) {
                this.onLocalStream(this.localStream);
            }
            
            console.log('Local media acquired');
            
        } catch (error) {
            console.error('Failed to get local media:', error);
            throw new Error('Camera/microphone access denied');
        }
    }
    
    /**
     * Create RTCPeerConnection with security configuration
     */
    async createPeerConnection() {
        try {
            this.peerConnection = new RTCPeerConnection(this.config);
            
            // Add local tracks
            if (this.localStream) {
                this.localStream.getTracks().forEach(track => {
                    this.peerConnection.addTrack(track, this.localStream);
                });
            }
            
            // Handle remote stream
            this.peerConnection.ontrack = (event) => {
                if (!this.remoteStream) {
                    this.remoteStream = new MediaStream();
                    if (this.onRemoteStream) {
                        this.onRemoteStream(this.remoteStream);
                    }
                }
                this.remoteStream.addTrack(event.track);
                console.log('Remote track added:', event.track.kind);
            };
            
            // Handle ICE candidates
            this.peerConnection.onicecandidate = (event) => {
                if (event.candidate) {
                    this.sendSignalingMessage({
                        type: 'ice-candidate',
                        call_id: this.callId,
                        candidate: {
                            candidate: event.candidate.candidate,
                            sdpMid: event.candidate.sdpMid,
                            sdpMLineIndex: event.candidate.sdpMLineIndex
                        }
                    });
                }
            };
            
            // Monitor connection state
            this.peerConnection.oniceconnectionstatechange = () => {
                console.log('ICE connection state:', this.peerConnection.iceConnectionState);
                
                if (this.peerConnection.iceConnectionState === 'connected') {
                    this.verifyEncryption();
                } else if (this.peerConnection.iceConnectionState === 'failed') {
                    console.error('ICE connection failed');
                    if (this.onError) this.onError(new Error('Connection failed'));
                    this.endCall();
                }
            };
            
            console.log('Peer connection created');
            
        } catch (error) {
            console.error('Failed to create peer connection:', error);
            throw error;
        }
    }
    
    /**
     * Create and send offer
     */
    async createOffer() {
        try {
            const offer = await this.peerConnection.createOffer({
                offerToReceiveAudio: true,
                offerToReceiveVideo: true
            });
            
            // Enforce encryption in SDP
            offer.sdp = this.enforceEncryption(offer.sdp);
            
            await this.peerConnection.setLocalDescription(offer);
            
            this.sendSignalingMessage({
                type: 'offer',
                call_id: this.callId,
                sdp: offer.sdp
            });
            
            console.log('Offer created and sent');
            
        } catch (error) {
            console.error('Failed to create offer:', error);
            throw error;
        }
    }
    
    /**
     * Create and send answer
     */
    async createAnswer() {
        try {
            const answer = await this.peerConnection.createAnswer();
            
            // Enforce encryption in SDP
            answer.sdp = this.enforceEncryption(answer.sdp);
            
            await this.peerConnection.setLocalDescription(answer);
            
            this.sendSignalingMessage({
                type: 'answer',
                call_id: this.callId,
                sdp: answer.sdp
            });
            
            console.log('Answer created and sent');
            
        } catch (error) {
            console.error('Failed to create answer:', error);
            throw error;
        }
    }
    
    /**
     * Enforce encryption in SDP
     */
    enforceEncryption(sdp) {
        // Ensure DTLS-SRTP is used
        if (!sdp.includes('a=fingerprint:')) {
            throw new Error('DTLS fingerprint missing - encryption not available');
        }
        
        // Remove unencrypted RTP if present
        sdp = sdp.replace(/m=audio.*RTP\/AVP/g, 'm=audio 9 UDP/TLS/RTP/SAVP');
        sdp = sdp.replace(/m=video.*RTP\/AVP/g, 'm=video 9 UDP/TLS/RTP/SAVP');
        
        console.log('Encryption enforced in SDP');
        return sdp;
    }
    
    /**
     * Verify encryption is active
     */
    async verifyEncryption() {
        try {
            const stats = await this.peerConnection.getStats();
            
            stats.forEach(report => {
                if (report.type === 'transport') {
                    console.log('DTLS State:', report.dtlsState);
                    console.log('SRTP Cipher:', report.srtpCipher);
                    console.log('DTLS Cipher:', report.dtlsCipher);
                    
                    if (report.dtlsState === 'connected') {
                        console.log('✅ Encryption verified: DTLS-SRTP active');
                        
                        if (this.onEncryptionVerified) {
                            this.onEncryptionVerified({
                                dtlsState: report.dtlsState,
                                srtpCipher: report.srtpCipher,
                                dtlsCipher: report.dtlsCipher
                            });
                        }
                    } else {
                        console.error('❌ DTLS not connected!');
                        throw new Error('Encryption not established');
                    }
                }
            });
            
        } catch (error) {
            console.error('Failed to verify encryption:', error);
            if (this.onError) this.onError(error);
            this.endCall();
        }
    }
    
    /**
     * Handle signaling messages
     */
    async handleSignalingMessage(data) {
        try {
            switch (data.type) {
                case 'connected':
                    console.log('Signaling connected, user ID:', data.user_id);
                    break;
                    
                case 'incoming_call':
                    console.log('Incoming call:', data);
                    // Handle in UI
                    break;
                    
                case 'call_accepted':
                    console.log('Call accepted');
                    break;
                    
                case 'call_rejected':
                    console.log('Call rejected');
                    this.cleanup();
                    if (this.onCallEnded) this.onCallEnded('rejected');
                    break;
                    
                case 'call_ended':
                    console.log('Call ended:', data.reason);
                    this.cleanup();
                    if (this.onCallEnded) this.onCallEnded(data.reason);
                    break;
                    
                case 'offer':
                    await this.handleOffer(data.sdp);
                    break;
                    
                case 'answer':
                    await this.handleAnswer(data.sdp);
                    break;
                    
                case 'ice-candidate':
                    await this.handleIceCandidate(data.candidate);
                    break;
                    
                case 'error':
                    console.error('Signaling error:', data.message);
                    if (this.onError) this.onError(new Error(data.message));
                    break;
                    
                default:
                    console.warn('Unknown signaling message:', data.type);
            }
        } catch (error) {
            console.error('Error handling signaling message:', error);
        }
    }
    
    /**
     * Handle offer from remote peer
     */
    async handleOffer(sdp) {
        try {
            // Validate SDP has encryption
            if (!sdp.includes('a=fingerprint:')) {
                throw new Error('Offer missing DTLS fingerprint - rejecting insecure call');
            }
            
            await this.peerConnection.setRemoteDescription({
                type: 'offer',
                sdp: sdp
            });
            
            await this.createAnswer();
            
        } catch (error) {
            console.error('Failed to handle offer:', error);
            throw error;
        }
    }
    
    /**
     * Handle answer from remote peer
     */
    async handleAnswer(sdp) {
        try {
            // Validate SDP has encryption
            if (!sdp.includes('a=fingerprint:')) {
                throw new Error('Answer missing DTLS fingerprint - rejecting insecure call');
            }
            
            await this.peerConnection.setRemoteDescription({
                type: 'answer',
                sdp: sdp
            });
            
        } catch (error) {
            console.error('Failed to handle answer:', error);
            throw error;
        }
    }
    
    /**
     * Handle ICE candidate from remote peer
     */
    async handleIceCandidate(candidate) {
        try {
            await this.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
        } catch (error) {
            console.error('Failed to add ICE candidate:', error);
        }
    }
    
    /**
     * Send signaling message via WebSocket
     */
    sendSignalingMessage(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        } else {
            console.error('WebSocket not connected');
        }
    }
    
    /**
     * Toggle audio mute
     */
    toggleAudio() {
        if (this.localStream) {
            const audioTrack = this.localStream.getAudioTracks()[0];
            if (audioTrack) {
                audioTrack.enabled = !audioTrack.enabled;
                return audioTrack.enabled;
            }
        }
        return false;
    }
    
    /**
     * Toggle video mute
     */
    toggleVideo() {
        if (this.localStream) {
            const videoTrack = this.localStream.getVideoTracks()[0];
            if (videoTrack) {
                videoTrack.enabled = !videoTrack.enabled;
                return videoTrack.enabled;
            }
        }
        return false;
    }
    
    /**
     * Cleanup resources
     */
    cleanup() {
        // Stop local stream
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
        }
        
        // Close peer connection
        if (this.peerConnection) {
            this.peerConnection.close();
            this.peerConnection = null;
        }
        
        // Close WebSocket
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        
        this.remoteStream = null;
        this.callId = null;
        
        console.log('Call resources cleaned up');
    }
}

// Export for use
window.SecureVideoCall = SecureVideoCall;
