# Threat Exposure Management Dashboard

Interactive Jupyter notebook dashboard for **Threat Exposure Management (July 2026)** presentations.

## Quick start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Open the notebook:
   ```bash
   jupyter notebook threat_exposure_dashboard.ipynb
   ```

3. Set your PowerPoint path in the notebook:
   ```python
   PPTX_PATH = r"C:\Users\GupteP\Downloads\Threat_Exposure_Management_July_2026.pptx"
   ```

4. Run all cells. The dashboard will:
   - Extract slide text and tables from your `.pptx`
   - Build KPI cards and interactive Plotly charts
   - Let you filter by severity, category, status, and exposure score
   - Export filtered data to `./extracted_data/`

## Notes

- If PPT tables do not match expected column names (`asset`, `severity`, `score`, etc.), the notebook uses sample data so you can still preview the layout.
- Edit `build_exposure_dataframe()` in the notebook to map your exact PPT column names.
