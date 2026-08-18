"""
End-to-End SSRF Pipeline Integration Test.
Runs a live local HTTP server simulating a PortSwigger SSRF stock-check vulnerability,
executes the full PenFlow pipeline (Crawler -> SSRFCapabilityAgent -> CAS -> CriticEngine -> ReportGenerator),
and outputs the complete certified Markdown & HackerOne report.
"""
import asyncio
import uvicorn
from fastapi import FastAPI, Form, Response
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI()

@app.get("/")
def home():
    return HTMLResponse("""
    <html>
        <body>
            <h1>Welcome to Our Store</h1>
            <a href="/product?productId=1">View Product 1</a>
        </body>
    </html>
    """)

@app.get("/product")
def view_product(productId: int = 1):
    return HTMLResponse(f"""
    <html>
        <body>
            <h1>Product {productId}</h1>
            <form action="/product/stock" method="POST">
                <input type="hidden" name="productId" value="{productId}">
                <input type="hidden" name="stockApi" value="http://stock.weliketoshop.net:8080/product/stock/check?productId={productId}">
                <button type="submit">Check stock</button>
            </form>
            <a href="/product/nextProduct?currentProductId={productId}&path=http://stock.weliketoshop.net">Next Product</a>
        </body>
    </html>
    """)

@app.get("/product/nextProduct")
def next_product(path: str = "/"):
    # Open redirect endpoint
    return Response(status_code=302, headers={"Location": path})

@app.post("/product/stock")
def check_stock(stockApi: str = Form(...)):
    # Vulnerable SSRF endpoint with whitelist bypass simulation
    # Accepts http://localhost#@stock.weliketoshop.net/admin or http://127.0.0.1%23@...
    # or open redirect chaining /product/nextProduct?path=http://192.168.0.12:8080/admin
    if "localhost" in stockApi or "127.0.0.1" in stockApi or "192.168.0" in stockApi:
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
            <head><title>Admin Panel</title></head>
            <body>
                <h1>Admin Panel</h1>
                <p>Welcome Administrator</p>
                <div>
                    <span>User: carlos</span>
                    <a href="/admin/delete?username=carlos">Delete user</a>
                </div>
            </body>
        </html>
        """)
    elif "169.254.169.254" in stockApi:
        return PlainTextResponse("ami-id\ninstance-id\nlocal-ipv4\npublic-keys")
    else:
        return PlainTextResponse("Stock: 84 units available")

async def run_test():
    import socket
    # Find free port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())

    # Wait for server to boot
    await asyncio.sleep(1.0)

    try:
        from penflow.app.web import execute_scan
        target = f"127.0.0.1:{port}"
        print(f"\n[+] Executing full live PenFlow scan against {target} ...\n")
        report_md = await execute_scan(target_domain=target)
        
        print("="*80)
        print("PENFLOW CERTIFIED END-TO-END SCAN REPORT")
        print("="*80)
        import os
        os.makedirs("reports", exist_ok=True)
        with open("reports/e2e_ssrf_verified_report.md", "w", encoding="utf-8") as f:
            f.write(report_md)
        print("\n[+] Report saved to reports/e2e_ssrf_verified_report.md")

        # Assertions
        assert "Server-Side Request Forgery" in report_md or "ssrf" in report_md.lower() or "CRITICAL" in report_md, "SSRF finding should be present in report!"
        assert "Total Findings | 0" not in report_md, "Report should contain certified verified findings!"
        print("\n🎉 LIVE END-TO-END PIPELINE TEST PASSED WITH CERTIFIED FINDING!")

    finally:
        server.should_exit = True
        await server_task

if __name__ == "__main__":
    asyncio.run(run_test())
