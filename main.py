from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import json
import os
import uuid
from datetime import datetime

app = FastAPI()

# CORS para tu frontend mobile
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Para móvil, permite todos los orígenes
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "auth_db.json"

# --- Helpers ---
def load_db():
    """Carga la base de datos desde JSON"""
    if not os.path.exists(DB_FILE):
        return {
            "owner_registered": False,
            "credential": None,
            "sessions": [],
            "created_at": None
        }
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(data):
    """Guarda la base de datos en JSON"""
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)

# --- 1. REGISTRO - SOLO UNA VEZ ---
@app.post("/api/auth/register")
async def register_credential(request: dict):
    """
    Registra la huella dactilar (credential de WebAuthn) del propietario
    Solo funciona una vez
    """
    db = load_db()
    
    if db["owner_registered"]:
        raise HTTPException(
            status_code=403, 
            detail="Esta app ya tiene dueño. Registro cerrado 🔒"
        )

    try:
        # Validar que venga credential data
        if not request.get("id"):
            raise HTTPException(status_code=400, detail="Credential inválido")

        # Guardamos la huella (credential de WebAuthn)
        db["credential"] = {
            "id": request.get("id"),
            "rawId": request.get("rawId"),
            "response": request.get("response"),
            "type": request.get("type", "public-key")
        }
        db["owner_registered"] = True
        db["created_at"] = datetime.now().isoformat()
        save_db(db)
        
        return {
            "success": True, 
            "message": "🎉 Huella de WebAuthn registrada. App sellada.",
            "owner": "Akiles"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- 2. LOGIN - SOLO TU HUELLA ---
@app.post("/api/auth/login")
async def login_credential(request: dict):
    """
    Verifica la huella dactilar del propietario
    Retorna un token de sesión
    """
    db = load_db()
    
    if not db["owner_registered"]:
        raise HTTPException(
            status_code=401, 
            detail="No hay huella registrada. Debes registrarte primero."
        )
    
    try:
        # Comparar el ID de la credencial
        credential_id = request.get("id")
        stored_id = db["credential"].get("id")
        
        if credential_id != stored_id:
            raise HTTPException(status_code=401, detail="❌ Huella no autorizada")

        # Generar sesión/token
        session_token = str(uuid.uuid4())
        session = {
            "token": session_token,
            "created_at": datetime.now().isoformat(),
            "user": "akiles"
        }
        
        db["sessions"].append(session)
        save_db(db)

        return {
            "success": True, 
            "user": "akiles",
            "token": session_token,
            "message": "✅ Bienvenido Akiles"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- 3. VERIFICAR SESIÓN ---
@app.get("/api/auth/verify")
async def verify_session(token: str = None):
    """Verifica si una sesión es válida"""
    if not token:
        raise HTTPException(status_code=401, detail="Token requerido")
    
    db = load_db()
    session = next((s for s in db["sessions"] if s["token"] == token), None)
    
    if not session:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    return {
        "valid": True,
        "user": session.get("user"),
        "created_at": session.get("created_at")
    }

# --- 4. LOGOUT ---
@app.post("/api/auth/logout")
async def logout(token: str = None):
    """Cierra la sesión del usuario"""
    if not token:
        raise HTTPException(status_code=401, detail="Token requerido")
    
    db = load_db()
    db["sessions"] = [s for s in db["sessions"] if s["token"] != token]
    save_db(db)
    
    return {"success": True, "message": "Sesión cerrada"}

# --- 5. STATUS ---
@app.get("/api/auth/status")
async def status():
    """Obtiene el estado de la autenticación"""
    db = load_db()
    return {
        "locked": db["owner_registered"],
        "owner": "akiles" if db["owner_registered"] else None,
        "registered_at": db.get("created_at"),
        "active_sessions": len(db["sessions"])
    }

# --- SERVIR HTML ---
@app.get("/")
async def serve_html():
    """Sirve el archivo HTML principal"""
    return FileResponse("index.html", media_type="text/html")

@app.get("/register.html")
async def serve_register():
    """Sirve la página de registro"""
    return FileResponse("register.html", media_type="text/html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
