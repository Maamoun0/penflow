import pytest
from pathlib import Path
from web.app import app
from penflow.config import Config

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_dashboard_route(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b"PenFlow" in response.data

def test_reports_list_route_empty(client, monkeypatch, tmp_path):
    # Mock config to point to a temporary scans directory
    config = Config.load()
    monkeypatch.setattr(config, "get", lambda key, default=None: str(tmp_path) if key == "scans.directory" else default)
    
    response = client.get('/reports')
    assert response.status_code == 200
    assert b"No reports found yet." in response.data

def test_reports_list_and_view_with_data(client, monkeypatch, tmp_path):
    # Setup mock reports structure
    target = "testtarget.com"
    target_dir = tmp_path / target
    target_dir.mkdir(parents=True, exist_ok=True)
    
    report_file = target_dir / "report_20260521.html"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("<h1>Mock HTML Report</h1>")
        
    report_md = target_dir / "report_20260521.md"
    with open(report_md, "w", encoding="utf-8") as f:
        f.write("# Mock MD Report")
        
    config = Config.load()
    monkeypatch.setattr(config, "get", lambda key, default=None: str(tmp_path) if key == "scans.directory" else default)
    
    # Test listing
    response = client.get('/reports')
    assert response.status_code == 200
    assert b"testtarget.com" in response.data
    assert b"report_20260521.html" in response.data
    
    # Test viewing HTML
    view_response = client.get(f'/reports/view/{target}/report_20260521.html')
    assert view_response.status_code == 200
    assert b"Mock HTML Report" in view_response.data
    
    # Test viewing MD
    view_md_response = client.get(f'/reports/view/{target}/report_20260521.md')
    assert view_md_response.status_code == 200
    assert b"Mock MD Report" in view_md_response.data
    
    # Test download
    download_response = client.get(f'/reports/download/{target}/report_20260521.html')
    assert download_response.status_code == 200
    assert download_response.headers.get("Content-Disposition") is not None
