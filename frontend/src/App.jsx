import { Routes, Route, Navigate } from 'react-router-dom'

// Prüfen App Pages
import Home from './pages/Prufen/Home'
import Scan from './pages/Prufen/Scan'
import Consent from './pages/Prufen/Consent'
import Success from './pages/Prufen/Success'

// Mock Verifier App Pages
import Login from './pages/MockVerifier/Login'

function App() {
    return (
        <Routes>
            {/* Prüfen App */}
            <Route path="/" element={<Home />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/consent/:request_id" element={<Consent />} />
            <Route path="/success" element={<Success />} />

            {/* Mock Verifier App - All in one unified interface */}
            <Route path="/mock-verifier" element={<Navigate to="/mock-verifier/login" replace />} />
            <Route path="/mock-verifier/login" element={<Login />} />
        </Routes>
    )
}

export default App
