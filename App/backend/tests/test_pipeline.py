import os

# pyrefly: ignore [missing-import]
# pyrefly: ignore [missing-import]
from fastapi.testclient import TestClient

from backend.app.analyzers.similarity_engine import HybridSimilarityEngine
from backend.app.analyzers.static_analyzer import StaticAnalyzer
from backend.app.demo.synthetic_apk import create_synthetic_test_apk
from backend.app.main import app

client = TestClient(app)

def test_system_status():
    response = client.get("/api/system/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert "default_weights" in data

def test_list_investigations():
    response = client.get("/api/investigations")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2

def test_investigation_detail():
    response = client.get("/api/investigations/1")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 1
    assert "SharkBot" in data["apk_name"] or "YONO" in data["apk_name"] or "sbi" in data["package_name"].lower()
    assert data["severity"] in ["HIGH", "CRITICAL"]
    assert len(data["risk_components"]) > 0

def test_static_analyzer_execution(tmp_path):
    test_apk = os.path.join(tmp_path, "test_banking.apk")
    create_synthetic_test_apk(test_apk, "banking_trojan")

    analyzer = StaticAnalyzer(test_apk)
    results = analyzer.analyze()

    assert "hashes" in results
    assert len(results["permissions"]) > 0
    assert len(results["extracted_urls"]) > 0
    assert any("sbi" in u.lower() for u in results["extracted_urls"])

def test_similarity_engine():
    features = [
        "android.permission.RECEIVE_SMS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "sbi-rewards-bonus.top",
        "WindowManager.addView"
    ]
    sim_engine = HybridSimilarityEngine(features)
    matches = sim_engine.calculate_similarity()
    assert len(matches) > 0
    top = matches[0]
    assert "SBI" in top["family_name"] or "Banking" in top["family_name"]
    assert top["similarity_score"] > 50

def test_ai_assistant_query():
    payload = {
        "investigation_id": 1,
        "query": "Why was this APK classified as high risk?"
    }
    response = client.post("/api/assistant/query", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert len(data["answer"]) > 10
    assert len(data["suggested_followups"]) > 0

def test_report_html_endpoint():
    response = client.get("/api/investigations/1/report/html")
    assert response.status_code == 200
    assert "FRAUDULENT APK AI THREAT REPORT" in response.text
