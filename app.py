
import re
import html
from io import StringIO

import pandas as pd
import plotly.express as px
import requests
import streamlit as st


# ============================================================
# CONFIGURACIÓN GENERAL
# ============================================================

st.set_page_config(
    page_title="SQL perdidos · patrones comerciales",
    page_icon="◉",
    layout="wide",
    initial_sidebar_state="expanded",
)

COLORS = {
    "red": "#D64545",
    "orange": "#D9822B",
    "yellow": "#C69A2D",
    "green": "#2F855A",
    "blue": "#3B6EA8",
    "purple": "#7253A6",
    "gray": "#667085",
    "ink": "#1F2937",
}

CATEGORY_COLORS = {
    "Casi cierre": COLORS["green"],
    "Ghosting post-propuesta/demo": COLORS["red"],
    "Mismatch explícito": COLORS["orange"],
    "Proyecto inmaduro / exploración": COLORS["yellow"],
    "Requisito / documentación": COLORS["purple"],
    "Necesidad ampliada + no respuesta": COLORS["blue"],
    "Proveedor actual / competencia": COLORS["gray"],
    "Pérdida sin evidencia suficiente": "#98A2B3",
}

SALES_USERS = [
    "ignacio",
    "monserrat",
    "montserrat",
    "jose galvan",
    "josé galvan",
]

PROFILE_USERS = [
    "nancy tovar",
    "valeria",
]

st.markdown(
    """
    <style>
        .block-container {padding-top: 1.4rem; padding-bottom: 3rem;}
        h1, h2, h3 {letter-spacing: -0.02em;}
        .small-note {color:#667085; font-size:0.86rem;}
        .metric-shell {
            border:1px solid #E5E7EB;
            border-radius:14px;
            padding:14px 16px;
            background:#FFFFFF;
            min-height:110px;
        }
        .metric-label {font-size:.82rem;color:#667085;margin-bottom:4px;}
        .metric-value {font-size:1.65rem;font-weight:700;color:#111827;}
        .metric-sub {font-size:.80rem;color:#667085;margin-top:3px;}
        .dot {
            height:10px;width:10px;border-radius:50%;
            display:inline-block;margin-right:7px;
        }
        .quote-box {
            border-left:4px solid #98A2B3;
            background:#F8FAFC;
            padding:12px 14px;
            margin:8px 0;
            border-radius:0 10px 10px 0;
            font-size:.94rem;
        }
        .case-card {
            border:1px solid #E5E7EB;
            border-radius:14px;
            padding:16px 18px;
            background:#FFFFFF;
            margin-bottom:12px;
        }
        .hypothesis {
            border:1px solid #E5E7EB;
            border-radius:14px;
            padding:16px 18px;
            background:#FFFFFF;
            min-height:170px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HELPERS DE TEXTO / COLUMNAS
# ============================================================

def norm_name(x):
    x = str(x or "").strip().lower()
    x = (
        x.replace("á", "a")
         .replace("é", "e")
         .replace("í", "i")
         .replace("ó", "o")
         .replace("ú", "u")
         .replace("ñ", "n")
    )
    x = re.sub(r"[^a-z0-9]+", "_", x).strip("_")
    return x


def clean_text(x):
    x = "" if x is None else str(x)
    x = re.sub(r"<br\s*/?>", "\n", x, flags=re.I)
    x = re.sub(r"<[^>]+>", "", x)
    x = x.replace("\\_", "_").replace("\\|", "|")
    x = html.unescape(x)
    x = re.sub(r"\n{3,}", "\n\n", x)
    return x.strip()


def safe_text(x):
    if pd.isna(x):
        return ""
    return str(x).strip()


def text_contains(text, patterns):
    t = norm_name(clean_text(text))
    return any(norm_name(p) in t for p in patterns)


def first_existing(df, aliases, required=False):
    mapping = {norm_name(c): c for c in df.columns}
    for alias in aliases:
        key = norm_name(alias)
        if key in mapping:
            return mapping[key]
    if required:
        raise KeyError(f"No encontré ninguna de estas columnas: {aliases}")
    return None


def normalize_deal_id(series):
    s = series.astype(str).str.strip()
    s = s.str.replace(r"\.0$", "", regex=True)
    s = s.replace({"nan": "", "None": "", "<NA>": ""})
    return s


def metric_card(label, value, sub="", color="#667085"):
    st.markdown(
        f"""
        <div class="metric-shell">
          <div class="metric-label">
            <span class="dot" style="background:{color};"></span>{html.escape(str(label))}
          </div>
          <div class="metric-value">{html.escape(str(value))}</div>
          <div class="metric-sub">{html.escape(str(sub))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


SENSITIVE_COLUMN_ALIASES = [
    "Nombre completo", "Nombre", "Full_Name", "full_name", "lead_name",
    "deal_name", "account_name", "Empresa", "Correo electrónico", "Correo",
    "email", "email_norm", "mobile", "Móvil", "Movil", "phone", "telefono",
    "Teléfono", "Sitio web", "website", "Callpicker_id"
]

def _sensitive_values(row):
    if row is None:
        return []
    cmap = {norm_name(c): c for c in row.index}
    deal_id = safe_text(row.get("deal_id", ""))
    vals = []
    for alias in SENSITIVE_COLUMN_ALIASES:
        col = cmap.get(norm_name(alias))
        if col:
            v = safe_text(row.get(col, ""))
            if len(v) >= 3 and v != deal_id:
                vals.append(v)
    return sorted(set(vals), key=len, reverse=True)

def redact_pii(text, row=None):
    text = clean_text(text)
    if not text:
        return ""
    text = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[EMAIL]", text, flags=re.I)
    text = re.sub(r"https?://\S+", "[URL]", text, flags=re.I)
    text = re.sub(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)", "[TELÉFONO]", text)
    deal_id = safe_text(row.get("deal_id", "")) if row is not None else ""
    def repl_long(m):
        return m.group(0) if m.group(0) == deal_id else "[NÚMERO]"
    text = re.sub(r"\b\d{7,}\b", repl_long, text)
    for value in _sensitive_values(row):
        text = re.sub(re.escape(value), "[DATO DEL LEAD]", text, flags=re.I)
    text = re.sub(r"\[(?:OPORTUNIDAD|CLIENTE)\s*-\s*[^\]]+\]", "[OPORTUNIDAD]", text, flags=re.I)
    return re.sub(r"\n{3,}", "\n\n", text).strip()

def quote_box(text, color="#98A2B3", row=None):
    text = redact_pii(text, row)
    if not text:
        return
    st.markdown(
        f'<div class="quote-box" style="border-left-color:{color};">{html.escape(text)}</div>',
        unsafe_allow_html=True,
    )


# ============================================================
# GOOGLE SHEETS PÚBLICO (SIN SERVICE ACCOUNT)
# ============================================================

def public_csv_url(spreadsheet_id, gid):
    return f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}/export?format=csv&gid={gid}"

@st.cache_data(ttl=300, show_spinner=False)
def load_worksheet(spreadsheet_id, gid):
    response = requests.get(public_csv_url(spreadsheet_id, gid), timeout=30)
    response.raise_for_status()
    if not response.text.strip():
        return pd.DataFrame()
    return pd.read_csv(StringIO(response.text), dtype=str, keep_default_na=False)

def load_all_sources():
    cfg = st.secrets["google_sheets"]
    sid = cfg["spreadsheet_id"]
    leads = load_worksheet(sid, cfg["leads_gid"])
    sales = load_worksheet(sid, cfg["sales_gid"])
    notes = load_worksheet(sid, cfg["notes_gid"])
    conversations = load_worksheet(sid, cfg["conversations_gid"])
    return leads, sales, notes, conversations


# ============================================================
# PREPARACIÓN DE FUENTES
# ============================================================

def prepare_sources(leads, sales, notes, conversations):
    # Deal IDs
    lead_deal_col = first_existing(
        leads,
        ["Id_Oportunidad", "deal_id", "Deal ID", "id_oportunidad"],
        required=True,
    )
    sales_deal_col = first_existing(
        sales,
        ["deal_id", "Deal ID", "Id_Oportunidad"],
        required=True,
    )
    notes_deal_col = first_existing(
        notes,
        ["deal_id", "Deal ID", "Id_Oportunidad"],
        required=True,
    )
    conv_deal_col = first_existing(
        conversations,
        ["deal_id", "Deal ID", "Id_Oportunidad"],
        required=True,
    )

    leads = leads.copy()
    sales = sales.copy()
    notes = notes.copy()
    conversations = conversations.copy()

    leads["deal_id"] = normalize_deal_id(leads[lead_deal_col])
    sales["deal_id"] = normalize_deal_id(sales[sales_deal_col])
    notes["deal_id"] = normalize_deal_id(notes[notes_deal_col])
    conversations["deal_id"] = normalize_deal_id(conversations[conv_deal_col])

    leads = leads[leads["deal_id"].ne("")]
    sales = sales[sales["deal_id"].ne("")]
    notes = notes[notes["deal_id"].ne("")]
    conversations = conversations[conversations["deal_id"].ne("")]

    # Una fila por deal_id en fuentes maestras
    leads = leads.drop_duplicates("deal_id", keep="last")
    sales = sales.drop_duplicates("deal_id", keep="last")

    return leads, sales, notes, conversations


# ============================================================
# NOTAS Y CONVERSACIONES
# ============================================================

def build_sales_notes(notes):
    creator_col = first_existing(notes, ["created_by_name", "created by name", "creado_por"])
    content_col = first_existing(notes, ["note_content", "content", "contenido_nota"])
    created_col = first_existing(notes, ["note_created_time", "created_time", "fecha_nota"])
    title_col = first_existing(notes, ["note_title", "title", "titulo_nota"])

    n = notes.copy()

    if creator_col:
        creator_norm = n[creator_col].astype(str).str.lower()
        sales_mask = creator_norm.apply(
            lambda x: any(name in x for name in SALES_USERS)
        )
        n = n[sales_mask].copy()

    if content_col is None:
        n["__content"] = ""
        content_col = "__content"

    def aggregate(group):
        rows = []
        if created_col:
            group = group.sort_values(created_col)
        for _, r in group.iterrows():
            date = safe_text(r.get(created_col, "")) if created_col else ""
            title = safe_text(r.get(title_col, "")) if title_col else ""
            body = clean_text(r.get(content_col, ""))

            prefix_parts = [x for x in [date, title] if x]
            prefix = " · ".join(prefix_parts)
            if prefix and body:
                rows.append(f"{prefix}\n{body}")
            elif body:
                rows.append(body)

        return pd.Series(
            {
                "sales_notes_text": "\n\n---\n\n".join(rows),
                "num_sales_notes": len(rows),
            }
        )

    if n.empty:
        return pd.DataFrame(columns=["deal_id", "sales_notes_text", "num_sales_notes"])

    return n.groupby("deal_id", dropna=False).apply(aggregate).reset_index()


def build_conversations(conversations):
    content_col = first_existing(
        conversations,
        ["conversation_clean", "conversation_text", "conversacion", "conversation"],
    )
    if content_col is None:
        conversations["__conversation"] = ""
        content_col = "__conversation"

    def aggregate(group):
        texts = []
        for x in group[content_col].tolist():
            tx = clean_text(x)
            if tx:
                texts.append(tx)

        return pd.Series(
            {
                "conversation_text_all": "\n\n---\n\n".join(texts),
                "num_conversations": len(texts),
            }
        )

    if conversations.empty:
        return pd.DataFrame(
            columns=["deal_id", "conversation_text_all", "num_conversations"]
        )

    return (
        conversations.groupby("deal_id", dropna=False)
        .apply(aggregate)
        .reset_index()
    )


# ============================================================
# MERGE PRINCIPAL
# ============================================================

def build_master(leads, sales, notes, conversations):
    notes_agg = build_sales_notes(notes)
    conv_agg = build_conversations(conversations)

    master = leads.merge(
        sales,
        on="deal_id",
        how="left",
        suffixes=("", "_sales"),
    )
    master = master.merge(notes_agg, on="deal_id", how="left")
    master = master.merge(conv_agg, on="deal_id", how="left")

    for c in ["sales_notes_text", "conversation_text_all"]:
        if c not in master:
            master[c] = ""
        master[c] = master[c].fillna("")

    for c in ["num_sales_notes", "num_conversations"]:
        if c not in master:
            master[c] = 0
        master[c] = pd.to_numeric(master[c], errors="coerce").fillna(0).astype(int)

    return master


# ============================================================
# MAPEO DE CAMPOS
# ============================================================

def map_fields(df):
    return {
        "fase": first_existing(df, ["Fase", "Stage"]),
        "motivo_perf": first_existing(df, ["Motivo (Perf)", "Motivo Perf", "motivo_perf"]),
        "estatus_cierre": first_existing(df, ["Estatus de cierre", "estatus_cierre"]),
        "ad_name": first_existing(df, ["ad_name", "Anuncio"]),
        "ad_value": first_existing(df, ["ad_value"]),
        "tamano": first_existing(
            df,
            ["Tamano_RevOps_Final", "Tamaño_RevOps_Final", "Tamaño de la empresa", "tamano"],
        ),
        "estado": first_existing(
            df,
            ["Estado/Provincia", "Estado", "state", "Provincia"],
        ),
        "necesidad": first_existing(
            df,
            [
                "¿Qué necesidad tiene tu empresa?",
                "Que necesidad tiene tu empresa",
                "necesidad",
            ],
        ),
        "decision": first_existing(
            df,
            [
                "¿A quiénes hay que involucrar para tomar la decis?",
                "A quienes hay que involucrar para tomar la decis",
                "decision",
            ],
        ),
        "presupuesto": first_existing(
            df,
            [
                "¿Qué presupuesto mensual estás considerando?",
                "Que presupuesto mensual estas considerando",
                "presupuesto",
            ],
        ),
        "usuarios_form": first_existing(
            df,
            [
                "¿Cuántas personas necesitan hacer o recibir?",
                "Cuantas personas necesitan hacer o recibir",
            ],
        ),
        "cotizacion": first_existing(
            df,
            ["cotizacion_enviada", "Cotización enviada", "cotizacion"],
        ),
        "num_cotizaciones": first_existing(
            df,
            ["num_cotizaciones", "Número de cotizaciones"],
        ),
        "promo_condiciones": first_existing(
            df,
            ["promo_condiciones_pago", "Promo o condiciones de pago"],
        ),
        "objetivo_buscado": first_existing(
            df,
            ["objetivo_buscado", "Qué objetivo buscas lograr resolviendo esto"],
        ),
        "personas_usarian": first_existing(
            df,
            ["personas_utilizarian_solucion", "Personas utilizarían solución"],
        ),
        "vendedor": first_existing(
            df,
            ["Vendedor", "vendedor"],
        ),
    }


def col_or_blank(df, col):
    if col and col in df.columns:
        return df[col].fillna("").astype(str)
    return pd.Series("", index=df.index, dtype="object")


# ============================================================
# FILTRO DE CASOS DESCARTADOS / PERDIDOS
# ============================================================

def filter_lost_cases(df, fields):
    fase = col_or_blank(df, fields["fase"])
    motivo = col_or_blank(df, fields["motivo_perf"])
    estatus = col_or_blank(df, fields["estatus_cierre"])

    # Reglas conservadoras:
    # 1) Cierre perdido / perdido
    # 2) además Motivo (Perf) contiene "Descartado"
    # Esto reproduce el criterio que se usó en el análisis.
    lost_mask = (
        fase.str.contains("Cierre Perdido", case=False, na=False)
        | estatus.str.contains("Perdido", case=False, na=False)
    )

    discarded_mask = motivo.str.contains("Descartado", case=False, na=False)

    result = df[lost_mask & discarded_mask].copy()

    # Nunca permitir Cierre Logrado
    result = result[
        ~col_or_blank(result, fields["fase"]).str.contains(
            "Cierre Logrado", case=False, na=False
        )
    ]

    return result


# ============================================================
# CLASIFICACIÓN CONSERVADORA
# ============================================================

def classify_row(row, fields):
    motivo = clean_text(row.get(fields["motivo_perf"], "")) if fields["motivo_perf"] else ""
    promo = clean_text(row.get(fields["promo_condiciones"], "")) if fields["promo_condiciones"] else ""
    objective = clean_text(row.get(fields["objetivo_buscado"], "")) if fields["objetivo_buscado"] else ""
    notes = clean_text(row.get("sales_notes_text", ""))
    conv = clean_text(row.get("conversation_text_all", ""))

    all_text = "\n".join([motivo, promo, objective, notes, conv])
    ntext = norm_name(all_text)

    # 1. Casi cierre: sólo evidencia explícita de paso a contratación/pago.
    near_close_patterns = [
        "liga de pago",
        "link de pago",
        "iniciaria con el plan",
        "iniciaría con el plan",
        "confirmo que iniciaria",
        "confirmó que iniciaría",
        "procedia para contratar",
        "procedía para contratar",
        "listo para contratar",
    ]
    if text_contains(all_text, near_close_patterns):
        return "Casi cierre"

    # 2. Proveedor actual / competencia explícita
    if text_contains(
        all_text,
        [
            "se queda con su proveedor actual",
            "se quedara con otra plataforma",
            "se quedará con otra plataforma",
            "se decidio por otro servicio",
            "se decidió por otro servicio",
            "competencia",
        ],
    ):
        return "Proveedor actual / competencia"

    # 3. Mismatch explícito
    mismatch_patterns = [
        "comprobante de domicilio",
        "planes moviles",
        "planes móviles",
        "telefonia movil con internet",
        "telefonía móvil con internet",
        "linea telefonica unicamente",
        "línea telefónica únicamente",
        "quiere utilizar su numero movil como principal",
        "quiere utilizar su número móvil como principal",
    ]
    if text_contains(all_text, mismatch_patterns):
        return "Mismatch explícito"

    # 4. Requisito / documentación
    if text_contains(
        all_text,
        [
            "sin documentos de validacion",
            "sin documentos de validación",
            "aun no tiene los documentos",
            "aún no tiene los documentos",
            "documentos de validacion",
            "documentos de validación",
        ],
    ):
        return "Requisito / documentación"

    # 5. Proyecto inmaduro / exploración
    if text_contains(
        all_text,
        [
            "curioseando",
            "solo estoy investigando",
            "sólo estoy investigando",
            "no es un proyecto",
            "no saben si en este ano o el proximo",
            "no saben si en este año o el próximo",
            "proyecto no listo",
            "falta de definicion de presupuesto",
            "falta de definición de presupuesto",
            "sin aprobacion final",
            "sin aprobación final",
        ],
    ):
        return "Proyecto inmaduro / exploración"

    # 6. Necesidad ampliada (ej. automatización) + no respuesta
    if (
        text_contains(
            all_text,
            [
                "respondiera en automatico",
                "respondiera en automático",
                "automatizacion",
                "automatización",
                "agente virtual",
                "inteligencia artificial",
            ],
        )
        and text_contains(
            all_text,
            ["no responde", "sin respuesta", "dejo de contestar", "dejó de contestar"],
        )
    ):
        return "Necesidad ampliada + no respuesta"

    # 7. Ghosting post-propuesta/demo sólo cuando existen AMBAS señales:
    #    avance + pérdida de contacto.
    has_advance = text_contains(
        all_text,
        [
            "propuesta enviada",
            "se envio propuesta",
            "se envió propuesta",
            "cotizacion enviada",
            "cotización enviada",
            "videollamada",
            "demo",
            "demostracion",
            "demostración",
            "propuesta comercial",
        ],
    )
    has_no_response = text_contains(
        all_text,
        [
            "no responde",
            "sin respuesta",
            "dejo de contestar",
            "dejó de contestar",
            "no se conecto",
            "no se conectó",
            "no asistio",
            "no asistió",
            "cuelga la llamada",
            "corta la llamada",
        ],
    )
    if has_advance and has_no_response:
        return "Ghosting post-propuesta/demo"

    return "Pérdida sin evidencia suficiente"


def classify_all(df, fields):
    result = df.copy()
    result["clasificacion"] = result.apply(
        lambda r: classify_row(r, fields),
        axis=1,
    )
    return result


# ============================================================
# EVIDENCIA
# ============================================================

def extract_evidence(row, fields, category):
    sources = []

    if fields["motivo_perf"]:
        val = clean_text(row.get(fields["motivo_perf"], ""))
        if val:
            sources.append(("Motivo CRM", val))

    if fields["promo_condiciones"]:
        val = clean_text(row.get(fields["promo_condiciones"], ""))
        if val:
            sources.append(("Proceso venta", val))

    notes = clean_text(row.get("sales_notes_text", ""))
    if notes:
        # Tomar párrafos útiles sin inventar.
        chunks = [x.strip() for x in re.split(r"\n\n---\n\n|\n", notes) if x.strip()]
        keywords = {
            "Casi cierre": ["liga de pago", "contratar", "plan de 200", "iniciaria", "iniciaría"],
            "Ghosting post-propuesta/demo": ["no responde", "no se conect", "propuesta", "videollamada", "demo"],
            "Mismatch explícito": ["comprobante", "planes moviles", "planes móviles", "linea telefonica", "línea telefónica", "numero movil", "número móvil"],
            "Proyecto inmaduro / exploración": ["no es un proyecto", "curioseando", "investigando", "proximo", "próximo", "luz verde"],
            "Requisito / documentación": ["document", "validacion", "validación"],
            "Necesidad ampliada + no respuesta": ["automatic", "automat", "agente virtual", "no responde"],
            "Proveedor actual / competencia": ["proveedor", "plataforma", "otro servicio"],
        }.get(category, [])

        picked = []
        for ch in chunks:
            nch = norm_name(ch)
            if any(norm_name(k) in nch for k in keywords):
                picked.append(ch)
            if len(picked) >= 3:
                break

        for p in picked:
            sources.append(("Nota ventas", p))

    conv = clean_text(row.get("conversation_text_all", ""))
    if conv:
        chunks = [x.strip() for x in re.split(r"\n\n---\n\n|\n", conv) if x.strip()]
        # Sólo líneas que no sean Nancy/Valeria y que tengan contenido comercial.
        picked = []
        for ch in chunks:
            low = ch.lower()
            if any(name in low for name in PROFILE_USERS):
                continue
            if any(
                k in norm_name(ch)
                for k in [
                    "propuesta", "demo", "pago", "contratar", "no_responde",
                    "recibido", "cotizacion", "cotización", "numero_empresarial",
                ]
            ):
                picked.append(ch)
            if len(picked) >= 2:
                break

        for p in picked:
            sources.append(("Conversación", p))

    # Deduplicar preservando orden
    seen = set()
    clean_sources = []
    for label, text in sources:
        key = norm_name(text)
        if key and key not in seen:
            seen.add(key)
            clean_sources.append((label, text))

    return clean_sources[:5]


# ============================================================
# APP DATA
# ============================================================

try:
    with st.spinner("Leyendo Google Sheets..."):
        leads, sales, notes, conversations = load_all_sources()
        leads, sales, notes, conversations = prepare_sources(
            leads, sales, notes, conversations
        )
        master = build_master(leads, sales, notes, conversations)
        fields = map_fields(master)
        lost = filter_lost_cases(master, fields)
        lost = classify_all(lost, fields)

except Exception as e:
    st.error("No fue posible cargar la información desde el Google Sheet público.")
    st.exception(e)
    st.stop()


# ============================================================
# CAMPOS ANALÍTICOS SIMPLES
# ============================================================

def add_display_columns(df, fields):
    out = df.copy()

    def value(name, default="Sin dato"):
        col = fields.get(name)
        if not col:
            return pd.Series(default, index=out.index)
        s = out[col].fillna("").astype(str).str.strip()
        return s.where(s.ne(""), default)

    out["ad_name_display"] = value("ad_name")
    out["ad_value_display"] = value("ad_value")
    out["tamano_display"] = value("tamano")
    out["estado_display"] = value("estado")
    out["necesidad_display"] = value("necesidad")
    out["decision_display"] = value("decision")
    out["presupuesto_display"] = value("presupuesto")
    out["cotizacion_display"] = value("cotizacion")
    out["usuarios_display"] = value("personas_usarian")
    out["motivo_display"] = value("motivo_perf")
    out["vendedor_display"] = value("vendedor")

    out["es_micro"] = out["tamano_display"].str.contains(
        "Microempresa", case=False, na=False
    )

    return out


lost = add_display_columns(lost, fields)


# ============================================================
# HEADER + FILTROS
# ============================================================

st.title("SQL perdidos · patrones del proceso comercial")
st.caption(
    "Oportunidades que calificaron a SQL y terminaron descartadas. "
    "Unidad de análisis: deal_id. Las clasificaciones son conservadoras y se sostienen con texto del CRM, notas o conversaciones."
)

st.sidebar.markdown("### Filtros")

ad_values = sorted(lost["ad_value_display"].dropna().unique().tolist())
sizes = sorted(lost["tamano_display"].dropna().unique().tolist())
states = sorted(lost["estado_display"].dropna().unique().tolist())
classes = list(CATEGORY_COLORS.keys())

f_ad = st.sidebar.multiselect("Oferta / ad_value", ad_values, default=ad_values)
f_size = st.sidebar.multiselect("Tamaño", sizes, default=sizes)
f_state = st.sidebar.multiselect("Estado", states, default=states)
f_class = st.sidebar.multiselect(
    "Clasificación",
    classes,
    default=[c for c in classes if c in lost["clasificacion"].unique()],
)

view = lost[
    lost["ad_value_display"].isin(f_ad)
    & lost["tamano_display"].isin(f_size)
    & lost["estado_display"].isin(f_state)
    & lost["clasificacion"].isin(f_class)
].copy()

st.sidebar.markdown("---")
st.sidebar.caption(
    "Filtro base: Cierre Perdido/Perdido + Motivo (Perf) que contiene “Descartado”. "
    "Nunca incluye Cierre Logrado."
)

tabs = st.tabs(
    [
        "1 · Descriptivos",
        "2 · Patrones e insights",
        "3 · Hipótesis",
    ]
)


# ============================================================
# TAB 1
# ============================================================

with tabs[0]:
    if view.empty:
        st.warning("No hay casos con los filtros seleccionados.")
    else:
        total = len(view)
        micro = int(view["es_micro"].sum())
        near = int((view["clasificacion"] == "Casi cierre").sum())
        mismatch = int((view["clasificacion"] == "Mismatch explícito").sum())
        ghost = int((view["clasificacion"] == "Ghosting post-propuesta/demo").sum())

        c1, c2, c3, c4, c5 = st.columns(5)

        with c1:
            metric_card("Casos", total, "deal_id únicos", COLORS["ink"])
        with c2:
            metric_card(
                "Microempresa",
                micro,
                f"{round(100*micro/total)}% del corte" if total else "0%",
                COLORS["orange"],
            )
        with c3:
            metric_card("Ghosting post-avance", ghost, "regla estricta", COLORS["red"])
        with c4:
            metric_card("Mismatch explícito", mismatch, "evidencia directa", COLORS["yellow"])
        with c5:
            metric_card("Casi cierre", near, "aceptación/pago explícito", COLORS["green"])

        st.markdown("### Clasificación de las pérdidas")
        counts = (
            view["clasificacion"]
            .value_counts()
            .rename_axis("Clasificación")
            .reset_index(name="Casos")
        )
        fig = px.bar(
            counts,
            x="Casos",
            y="Clasificación",
            orientation="h",
            color="Clasificación",
            color_discrete_map=CATEGORY_COLORS,
            text="Casos",
        )
        fig.update_layout(
            height=420,
            showlegend=False,
            xaxis_title="Casos",
            yaxis_title="",
            margin=dict(l=10, r=10, t=20, b=10),
        )
        st.plotly_chart(fig, use_container_width=True)

        c1, c2 = st.columns(2)

        with c1:
            st.markdown("### Tamaño")
            tmp = (
                view["tamano_display"]
                .value_counts()
                .rename_axis("Tamaño")
                .reset_index(name="Casos")
            )
            fig = px.bar(
                tmp,
                x="Casos",
                y="Tamaño",
                orientation="h",
                text="Casos",
            )
            fig.update_layout(height=350, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.markdown("### Estado")
            tmp = (
                view["estado_display"]
                .value_counts()
                .rename_axis("Estado")
                .reset_index(name="Casos")
            )
            fig = px.bar(
                tmp,
                x="Casos",
                y="Estado",
                orientation="h",
                text="Casos",
            )
            fig.update_layout(height=350, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Oferta × clasificación")
        matrix = (
            view.groupby(["ad_value_display", "clasificacion"])
            .size()
            .reset_index(name="Casos")
        )
        fig = px.bar(
            matrix,
            x="ad_value_display",
            y="Casos",
            color="clasificacion",
            color_discrete_map=CATEGORY_COLORS,
            barmode="stack",
        )
        fig.update_layout(
            xaxis_title="ad_value",
            yaxis_title="Casos",
            legend_title="",
            height=430,
        )
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Casos")
        st.dataframe(
            view[
                [
                    "deal_id",
                    "ad_name_display",
                    "ad_value_display",
                    "tamano_display",
                    "estado_display",
                    "necesidad_display",
                    "decision_display",
                    "presupuesto_display",
                    "cotizacion_display",
                    "clasificacion",
                    "motivo_display",
                ]
            ],
            use_container_width=True,
            hide_index=True,
            column_config={
                "deal_id": "deal_id",
                "ad_name_display": "Anuncio",
                "ad_value_display": "Oferta",
                "tamano_display": "Tamaño",
                "estado_display": "Estado",
                "necesidad_display": st.column_config.TextColumn(
                    "Necesidad", width="large"
                ),
                "decision_display": "Decisión",
                "presupuesto_display": "Presupuesto",
                "cotizacion_display": "Cotización",
                "clasificacion": "Clasificación",
                "motivo_display": st.column_config.TextColumn(
                    "Motivo CRM", width="large"
                ),
            },
        )

        st.info(
            "Los descriptivos muestran concentración dentro de los descartados. "
            "No prueban por sí solos que un tamaño, estado o anuncio tenga peor tasa de cierre: "
            "para eso hay que comparar contra todos los SQL y cierres."
        )


# ============================================================
# TAB 2
# ============================================================

with tabs[1]:
    st.markdown("## Casos que requieren revisión")

    if view.empty:
        st.warning("No hay casos con los filtros seleccionados.")
    else:
        # Especial 1: casi cierre
        st.markdown("### 1. Casi cierre")
        near_close = view[view["clasificacion"] == "Casi cierre"]

        if near_close.empty:
            st.caption("No hay un caso de casi cierre dentro de los filtros actuales.")
        else:
            for _, row in near_close.iterrows():
                st.markdown(
                    f"""
                    <div class="case-card">
                        <b><span class="dot" style="background:{COLORS['green']};"></span>
                        {html.escape(row['deal_id'])}</b><br>
                        <span class="small-note">{html.escape(row['ad_value_display'])}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.write(
                    "**Por qué entra aquí:** sólo se usa “Casi cierre” cuando existe texto explícito "
                    "de contratación/elección del plan o liga de pago."
                )

                evidence = extract_evidence(row, fields, row["clasificacion"])
                for label, text in evidence:
                    st.caption(label)
                    quote_box(text, COLORS["green"], row)

        st.markdown("---")

        # Especial 2: necesidad inicial vs revelada
        st.markdown("### 2. Entraron con una necesidad y después apareció otra")
        changed = view[
            view["clasificacion"].isin(
                ["Mismatch explícito", "Necesidad ampliada + no respuesta"]
            )
        ]

        if changed.empty:
            st.caption("No hay casos de este tipo dentro de los filtros actuales.")
        else:
            for _, row in changed.iterrows():
                color = CATEGORY_COLORS[row["clasificacion"]]
                st.markdown(
                    f"""
                    <div class="case-card">
                        <b><span class="dot" style="background:{color};"></span>
                        {html.escape(row['clasificacion'])}</b>
                        &nbsp;·&nbsp;<code>{html.escape(row['deal_id'])}</code><br>
                        <span class="small-note">
                        <b>Oferta:</b> {html.escape(row['ad_value_display'])}<br>
                        <b>Necesidad de entrada:</b> {html.escape(row['necesidad_display'])}
                        </span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                evidence = extract_evidence(row, fields, row["clasificacion"])
                for label, text in evidence:
                    st.caption(label)
                    quote_box(text, color, row)

        st.markdown("---")

        # Especial 3: extremos
        st.markdown("### 3. Casos atípicos / extremos")
        extreme_categories = [
            "Mismatch explícito",
            "Requisito / documentación",
            "Proveedor actual / competencia",
        ]
        extreme = view[view["clasificacion"].isin(extreme_categories)]

        if extreme.empty:
            st.caption("No hay casos extremos dentro de los filtros actuales.")
        else:
            for _, row in extreme.iterrows():
                with st.expander(
                    f"{row['deal_id']} · {row['clasificacion']} · {row['ad_value_display']}"
                ):
                    st.write("**Necesidad de entrada**")
                    st.write(row["necesidad_display"])

                    st.write("**Motivo registrado**")
                    st.write(row["motivo_display"])

                    evidence = extract_evidence(row, fields, row["clasificacion"])
                    for label, text in evidence:
                        st.caption(label)
                        quote_box(text, CATEGORY_COLORS[row["clasificacion"]], row)

        st.markdown("---")
        st.markdown("## Explorador por deal_id")

        selected = st.selectbox(
            "Deal",
            options=view["deal_id"].tolist(),
            format_func=lambda x: (
                f"{x} · "
                f"{view.loc[view['deal_id'].eq(x), 'clasificacion'].iloc[0]}"
            ),
        )

        row = view[view["deal_id"] == selected].iloc[0]
        color = CATEGORY_COLORS.get(row["clasificacion"], COLORS["gray"])

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            metric_card("Clasificación", row["clasificacion"], "regla conservadora", color)
        with c2:
            metric_card("Tamaño", row["tamano_display"], row["estado_display"], COLORS["orange"])
        with c3:
            metric_card("Cotización", row["cotizacion_display"], row["presupuesto_display"], COLORS["blue"])
        with c4:
            metric_card("Decisión", row["decision_display"], row["usuarios_display"], COLORS["purple"])

        st.markdown("**Oferta del anuncio**")
        st.write(row["ad_value_display"])

        st.markdown("**Necesidad registrada**")
        st.write(row["necesidad_display"])

        st.markdown("**Motivo CRM**")
        st.write(row["motivo_display"])

        st.markdown("**Evidencia textual seleccionada**")
        evidence = extract_evidence(row, fields, row["clasificacion"])
        if not evidence:
            st.caption("No se encontró un extracto adicional suficientemente claro.")
        else:
            for label, text in evidence:
                st.caption(label)
                quote_box(text, color, row)

        with st.expander("Notas de ventas · versión sanitizada"):
            notes_text = redact_pii(row.get("sales_notes_text", ""), row)
            if notes_text:
                st.text(notes_text)
            else:
                st.caption("Sin notas de ventas disponibles.")

        with st.expander("Conversaciones · versión sanitizada"):
            conv_text = redact_pii(row.get("conversation_text_all", ""), row)
            if conv_text:
                st.text(conv_text)
            else:
                st.caption("Sin conversación disponible.")

        with st.expander("Reglas exactas de clasificación"):
            st.markdown(
                """
                - **Casi cierre:** existe evidencia explícita de contratación/elección del plan, liga de pago o paso equivalente.
                - **Ghosting post-propuesta/demo:** existen simultáneamente una señal explícita de avance (propuesta/demo/cotización) y una señal posterior de no respuesta/no-show.
                - **Mismatch explícito:** la necesidad final registrada corresponde claramente a otro servicio o requisito no cubierto por la oferta.
                - **Proyecto inmaduro / exploración:** el propio texto menciona curiosidad, falta de proyecto, falta de aprobación, timing o proyecto no listo.
                - **Requisito / documentación:** un requisito documental/operativo impide avanzar.
                - **Necesidad ampliada + no respuesta:** la necesidad se amplía hacia automatización/IA u otro alcance, pero no hay evidencia suficiente para llamarla incompatibilidad total.
                - **Proveedor actual / competencia:** el CRM/nota dice explícitamente que se queda con otro proveedor/plataforma/servicio.
                - **Pérdida sin evidencia suficiente:** no hay texto suficiente para usar una etiqueta más específica.
                """
            )


# ============================================================
# TAB 3
# ============================================================

with tabs[2]:
    st.markdown("## Hipótesis")
    st.caption(
        "Estas tarjetas no son conclusiones causales. Cada una muestra una señal descriptiva del corte y qué habría que medir para confirmarla."
    )

    if lost.empty:
        st.warning("No hay casos descartados con el filtro base.")
    else:
        total = len(lost)
        ghost_n = int((lost["clasificacion"] == "Ghosting post-propuesta/demo").sum())
        near_n = int((lost["clasificacion"] == "Casi cierre").sum())
        mismatch_n = int((lost["clasificacion"] == "Mismatch explícito").sum())
        micro_n = int(lost["es_micro"].sum())

        c1, c2 = st.columns(2)

        with c1:
            st.markdown(
                f"""
                <div class="hypothesis">
                    <b><span class="dot" style="background:{COLORS['red']};"></span>
                    H1 · Parte de la fuga ocurre después de avance comercial</b><br><br>
                    <b>{ghost_n + near_n}/{total}</b> casos están clasificados como ghosting post-propuesta/demo o casi cierre.<br><br>
                    <span class="small-note">
                    Esto localiza la fuga; no explica por qué el prospecto dejó de responder.
                    </span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c2:
            st.markdown(
                f"""
                <div class="hypothesis">
                    <b><span class="dot" style="background:{COLORS['orange']};"></span>
                    H2 · Parte de la oferta admite interpretaciones diferentes</b><br><br>
                    <b>{mismatch_n}/{total}</b> casos tienen mismatch explícito en el texto disponible.<br><br>
                    <span class="small-note">
                    Debe probarse con una variante de copy y midiendo fit real después de la primera llamada.
                    </span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.write("")
        c3, c4 = st.columns(2)

        with c3:
            st.markdown(
                """
                <div class="hypothesis">
                    <b><span class="dot" style="background:#3B6EA8;"></span>
                    H3 · Cotización enviada puede estar midiendo actividad, no intención</b><br><br>
                    Hay pérdidas después de propuestas/cotizaciones, por lo que conviene separar:
                    enviada → revisada → respondió → negoció → aceptó → pagó.<br><br>
                    <span class="small-note">
                    Comparar tasas entre etapas antes de atribuir el problema a la calidad del lead.
                    </span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c4:
            st.markdown(
                f"""
                <div class="hypothesis">
                    <b><span class="dot" style="background:{COLORS['yellow']};"></span>
                    H4 · Las pérdidas están concentradas en microempresas</b><br><br>
                    <b>{micro_n}/{total}</b> descartados son microempresas dentro de este corte.<br><br>
                    <span class="small-note">
                    No implica que cierren peor. Hay que comparar contra todos los SQL y todos los cierres por tamaño.
                    </span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("### Qué medir para confirmar o rechazar")
        st.markdown(
            """
            **H1 — Post-avance:** timestamps y estados para `demo`, `cotización enviada`, `cotización revisada`, `aceptación`, `liga de pago`, `pago`.

            **H2 — Fit del anuncio:** etiquetar después de la primera conversación `fit correcto / fit parcial / mismatch`, y cruzarlo con `ad_value`.

            **H3 — Cotización:** medir `cotización enviada → respuesta`, `cotización revisada → negociación` y `negociación → cierre`.

            **H4 — Tamaño:** comparar `SQL → cierre` por tamaño de empresa usando la población completa, no sólo los perdidos.
            """
        )

        st.warning(
            "El dashboard no atribuye causalidad a precio, vendedor, tamaño, estado o anuncio cuando el texto disponible no lo sostiene."
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")
st.caption(
    "Fuente: Google Sheets público · cruce por deal_id · único identificador visible: deal_id · actualización cada ~5 minutos."
)
