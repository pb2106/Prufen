import { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { ShieldCheck, CheckCircle2, XCircle, Clock, Trash2, Lock, AlertCircle, ArrowLeft } from 'lucide-react';
import api from '../../services/api';
import { buildPoseidon } from 'circomlibjs';

export default function Consent() {
    const { request_id } = useParams();
    const location = useLocation();
    const navigate = useNavigate();

    const [currentUser, setCurrentUser] = useState(null);
    const [showUserSelector, setShowUserSelector] = useState(false);
    const [request, setRequest] = useState(location.state?.request || null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        const userId = localStorage.getItem('mock_user_id');
        const userName = localStorage.getItem('user_name');

        if (userId && userName) {
            setCurrentUser({ id: userId, name: userName });
        } else {
            setShowUserSelector(true);
        }

        if (!request) {
            fetchRequestDetails();
        }
    }, [request_id]);

    const selectUser = (user) => {
        localStorage.setItem('mock_user_id', user.id);
        localStorage.setItem('user_name', user.name);
        setCurrentUser(user);
        setShowUserSelector(false);
    };

    const fetchRequestDetails = async () => {
        try {
            const res = await api.get(`/proof-requests/${request_id}`);
            setRequest(res.data);
        } catch (err) {
            setError('Proof request not found or expired');
            console.error(err);
        }
    };

    const handleApprove = async () => {
        if (!currentUser) {
            setShowUserSelector(true);
            return;
        }

        setLoading(true);
        setError(null);

        try {
            // --- 1. LOCAL CREDENTIAL ISSUANCE (If not already present) ---
            // In a real app, the user would already have this in their wallet.
            // For the demo, we generate it on the fly but store it locally.
            let credential = JSON.parse(localStorage.getItem(`credential_${currentUser.id}`) || 'null');
            let birthDate = JSON.parse(localStorage.getItem(`birthdate_${currentUser.id}`) || 'null');

            if (!credential) {
                // Mock user data
                const birthYear = currentUser.id === 'usr_demo_adult' ? 1990 : 2010;
                const birthMonth = 1;
                const birthDay = 1;
                const salt = Math.floor(Math.random() * 1000000000);

                birthDate = { birthYear, birthMonth, birthDay, salt };
                localStorage.setItem(`birthdate_${currentUser.id}`, JSON.stringify(birthDate));

                // Compute Poseidon commitment locally
                const poseidon = await buildPoseidon();
                const F = poseidon.F;
                const hash = poseidon([birthYear, birthMonth, birthDay, salt]);
                const commitment = F.toString(hash);

                // Get signed credential from Issuer (Port 8001)
                const issuerRes = await fetch('http://localhost:8001/issue-credential', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': 'issuer-dev-key-change-in-production' // From issuer/.env.example
                    },
                    body: JSON.stringify({
                        commitment: commitment,
                        user_id: currentUser.id
                    })
                });

                if (!issuerRes.ok) {
                    throw new Error('Failed to obtain credential from Issuer');
                }

                credential = await issuerRes.json();
                localStorage.setItem(`credential_${currentUser.id}`, JSON.stringify(credential));
            }

            // --- 2. LOCAL ZK PROOF GENERATION ---
            const today = new Date();
            const currentYear = today.getFullYear();
            const currentMonth = today.getMonth() + 1;
            const currentDay = today.getDate();

            let minAge = 0;
            if (request.claim_type === 'age_over_18') minAge = 18;
            else if (request.claim_type === 'age_over_21') minAge = 21;

            const input = {
                birthYear: birthDate.birthYear,
                birthMonth: birthDate.birthMonth,
                birthDay: birthDate.birthDay,
                salt: birthDate.salt,
                currentYear,
                currentMonth,
                currentDay,
                minAge,
                commitment: credential.commitment
            };

            // Generate proof using window.snarkjs (loaded via script tag in index.html)
            const { proof, publicSignals } = await window.snarkjs.groth16.fullProve(
                input,
                "/zk/age_verify.wasm",
                "/zk/age_verify_final.zkey"
            );

            // Generate a random nullifier to prevent replay attacks
            const nullifier_hash = Array.from(crypto.getRandomValues(new Uint8Array(16)))
                .map(b => b.toString(16).padStart(2, '0')).join('');

            // --- 3. SEND ZK PROOF TO BACKEND (DOB is NOT sent) ---
            const res = await api.post(`/proof-requests/${request_id}/approve`, {
                proof: proof,
                public_signals: publicSignals,
                nullifier_hash: nullifier_hash
            });

            if (request.callback_url) {
                // GUARD: If running on Cloudflare/remote but callback is localhost, SKIP IT.
                // This prevents CORS errors from stale QR codes or default backend config.
                const isLocalhostCallback = request.callback_url.includes('localhost') || request.callback_url.includes('127.0.0.1');
                const isRemoteOrigin = window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1';

                if (isRemoteOrigin && isLocalhostCallback) {
                    console.warn('Skipping localhost callback because we are on a remote origin:', request.callback_url);
                } else {
                    try {
                        await fetch(request.callback_url, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                proof_request_id: request_id,
                                proof_id: res.data.proof_id,
                                status: 'approved',
                                timestamp: new Date().toISOString()
                            })
                        });
                    } catch (callbackErr) {
                        console.error('Failed to send to callback:', callbackErr);
                    }
                }
            }

            navigate('/success');
        } catch (err) {
            setError(err.response?.data?.detail || 'Approval failed');
        }

        setLoading(false);
    };

    if (showUserSelector) {
        return (
            <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
                <div className="bg-white rounded-xl shadow-lg max-w-md w-full p-8 border border-slate-100">
                    <h2 className="text-2xl font-bold text-slate-900 mb-2 text-center">Select Demo Persona</h2>
                    <p className="text-slate-500 mb-6 text-center">Who are you acting as for this test?</p>
                    <div className="space-y-3">
                        <button
                            onClick={() => selectUser({ id: 'usr_demo_adult', name: 'John Doe' })}
                            className="w-full text-left p-4 bg-slate-50 border border-slate-200 rounded-xl hover:bg-white hover:shadow-md transition-all group"
                        >
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="font-bold text-slate-900 group-hover:text-blue-600">John Doe (Adult)</p>
                                    <p className="text-sm text-slate-500">Age: 34 • Resident</p>
                                </div>
                                <div className="h-3 w-3 rounded-full bg-green-500"></div>
                            </div>
                        </button>
                        <button
                            onClick={() => selectUser({ id: 'usr_demo_teen', name: 'Jane Smith' })}
                            className="w-full text-left p-4 bg-slate-50 border border-slate-200 rounded-xl hover:bg-white hover:shadow-md transition-all group"
                        >
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="font-bold text-slate-900 group-hover:text-blue-600">Jane Smith (Teen)</p>
                                    <p className="text-sm text-slate-500">Age: 14 • Student</p>
                                </div>
                                <div className="h-3 w-3 rounded-full bg-blue-500"></div>
                            </div>
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    if (error && !request) {
        return (
            <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
                <div className="bg-white rounded-xl shadow-lg max-w-md w-full p-8 text-center border border-slate-100">
                    <div className="w-16 h-16 bg-red-50 rounded-full flex items-center justify-center mx-auto mb-4">
                        <XCircle className="w-8 h-8 text-red-500" />
                    </div>
                    <h1 className="text-xl font-bold text-slate-900 mb-2">Request Not Found</h1>
                    <p className="text-slate-500 mb-8">{error}</p>
                    <button onClick={() => navigate('/')} className="bg-slate-900 text-white px-6 py-3 rounded-lg font-medium hover:bg-slate-800 transition-colors">
                        Return Home
                    </button>
                </div>
            </div>
        );
    }

    if (!request) {
        return (
            <div className="min-h-screen bg-slate-50 flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-4 border-slate-200 border-t-slate-900"></div>
            </div>
        );
    }

    const claimDisplay = request.claim?.display || request.claim_display;
    const isStudent = request.claim_type === 'student_status';
    const isResidency = request.claim_type === 'residency_US';

    const handleDecline = async () => {
        try {
            await api.post(`/proof-requests/${request_id}/reject`);
        } catch (err) {
            console.error('Failed to reject request:', err);
        }
        navigate('/');
    };

    return (
        <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4 font-sans">
            <div className="bg-white rounded-2xl shadow-xl border border-slate-100 max-w-md w-full overflow-hidden relative">
                {/* User Badge */}
                {currentUser && (
                    <div className="absolute top-4 right-4 z-10">
                        <button
                            onClick={() => setShowUserSelector(true)}
                            className="flex items-center space-x-2 bg-slate-100 hover:bg-slate-200 px-3 py-1.5 rounded-full text-xs font-medium text-slate-600 transition-colors"
                        >
                            <div className={`w-2 h-2 rounded-full ${currentUser.id === 'usr_demo_adult' ? 'bg-green-500' : 'bg-blue-500'}`}></div>
                            <span>{currentUser.name}</span>
                        </button>
                    </div>
                )}

                {/* Header */}
                <div className="p-6 border-b border-slate-100">
                    <div className="flex items-center justify-between mb-6">
                        <button onClick={handleDecline} className="text-slate-400 hover:text-slate-600">
                            <ArrowLeft className="w-5 h-5" />
                        </button>
                        <div className="flex items-center text-slate-900 font-bold">
                            <ShieldCheck className="w-5 h-5 mr-2 text-slate-900" />
                            Prüfen
                        </div>
                        <div className="w-5"></div>
                    </div>
                    <div className="text-center">
                        <h1 className="text-xl font-bold text-slate-900 mb-1">Verification Request</h1>
                        <p className="text-sm text-slate-500">
                            <span className="font-semibold text-slate-900">{request.verifier?.name || request.verifier_name}</span> is requesting proof.
                        </p>
                    </div>
                </div>

                <div className="p-6">
                    {/* Claim Display */}
                    <div className="bg-slate-50 rounded-xl p-6 text-center mb-6 border border-slate-100">
                        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">They want to verify</p>
                        <p className="text-lg font-medium text-slate-900">
                            {isStudent ? 'Student Status' : isResidency ? 'US Residency' : claimDisplay}
                        </p>
                    </div>

                    {/* Privacy Disclosure */}
                    <div className="space-y-4 mb-8">
                        <div className="flex items-start">
                            <div className="flex-shrink-0 mt-0.5">
                                <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                            </div>
                            <div className="ml-3">
                                <p className="text-sm font-semibold text-slate-900">They will receive</p>
                                <p className="text-xs text-slate-500 mt-0.5">A simple YES or NO confirmation only.</p>
                            </div>
                        </div>
                        <div className="flex items-start">
                            <div className="flex-shrink-0 mt-0.5">
                                <XCircle className="w-5 h-5 text-slate-300" />
                            </div>
                            <div className="ml-3">
                                <p className="text-sm font-semibold text-slate-900">They will NOT see</p>
                                <p className="text-xs text-slate-500 mt-0.5">Your private details or raw ID data.</p>
                            </div>
                        </div>
                    </div>

                    {/* Meta Info */}
                    <div className="grid grid-cols-3 gap-2 mb-8">
                        <div className="flex flex-col items-center text-center p-2">
                            <Clock className="w-4 h-4 text-slate-400 mb-1" />
                            <span className="text-[10px] text-slate-500">Expires in 5m</span>
                        </div>
                        <div className="flex flex-col items-center text-center p-2">
                            <Trash2 className="w-4 h-4 text-slate-400 mb-1" />
                            <span className="text-[10px] text-slate-500">Deleted after use</span>
                        </div>
                        <div className="flex flex-col items-center text-center p-2">
                            <Lock className="w-4 h-4 text-slate-400 mb-1" />
                            <span className="text-[10px] text-slate-500">Single verifier</span>
                        </div>
                    </div>

                    {error && (
                        <div className="mb-6 bg-red-50 border border-red-100 text-red-600 p-3 rounded-lg text-sm flex items-center">
                            <AlertCircle className="w-4 h-4 mr-2 flex-shrink-0" />
                            {error}
                        </div>
                    )}

                    <button
                        onClick={handleApprove}
                        disabled={loading}
                        className="w-full bg-slate-900 hover:bg-slate-800 text-white p-4 rounded-xl font-bold mb-3 disabled:opacity-70 disabled:cursor-not-allowed transition-all shadow-md active:scale-[0.98]"
                    >
                        {loading ? (
                            <span className="flex items-center justify-center">
                                <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent mr-2"></div>
                                Generating Proof...
                            </span>
                        ) : (
                            'Approve Verification'
                        )}
                    </button>
                    <button onClick={handleDecline} className="w-full text-slate-500 hover:text-slate-700 p-3 font-medium text-sm transition-colors">
                        Decline Request
                    </button>
                </div>
                <div className="bg-slate-50 p-4 text-center border-t border-slate-100">
                    <p className="text-[10px] text-slate-400 flex items-center justify-center">
                        <Lock className="w-3 h-3 mr-1" />
                        Zero-Knowledge Proof Protocol
                    </p>
                </div>
            </div>
        </div>
    );
}
