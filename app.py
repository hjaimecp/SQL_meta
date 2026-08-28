
import re
import html
from io import StringIO

import pandas as pd
import plotly.express as px
import requests
import streamlit as st


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
    "Proveedor actual / competencia": COLORS["gray"],
}

SALES_USERS = ["ignacio", "monserrat", "montserrat", "jose galvan", "josé galvan"]
PROFILE_USERS = ["nancy tovar", "valeria"]

st.markdown(
    """
    <style>
        .block-container {padding-top: 1.4rem; padding-bottom: 3rem;}
        h1, h2, h3 {letter-spacing: -0.02em;}
        .small-note {color:#667085; font-size:0.86rem;}
        .metric-shell {
            border:1px solid #E5E7EB;border-radius:14px;padding:14px 16px;
            background:#FFFFFF;min-height:110px;
        }
        .metric-label {font-size:.82rem;color:#667085;margin-bottom:4px;}
        .metric-value {font-size:1.65rem;font-weight:700;color:#111827;}
        .metric-sub {font-size:.80rem;color:#667085;margin-top:3px;}
        .dot {height:10px;width:10px;border-radius:50%;display:inline-block;margin-right:7px;}
        .quote-box {
            border-left:4px solid #98A2B3;
            background:rgba(148, 163, 184, 0.10);
            color:inherit;
            padding:12px 14px;
            margin:8px 0;
            border-radius:0 10px 10px 0;
            font-size:.94rem;
        }
        .case-card {
            border:1px solid #E5E7EB;border-radius:14px;padding:16px 18px;
            background:#FFFFFF;margin-bottom:12px;
        }
        .hypothesis {
            border:1px solid rgba(148,163,184,.35);
            border-radius:14px;
            padding:16px 18px;
            background:rgba(148,163,184,.10);
            color:inherit;
            min-height:170px;
        }
        .hypothesis b, .hypothesis span {
            color:inherit !important;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def norm_name(x):
    x = str(x or "").strip().lower()
    for a, b in [("á","a"),("é","e"),("í","i"),("ó","o"),("ú","u"),("ñ","n")]:
        x = x.replace(a, b)
    return re.sub(r"[^a-z0-9]+", "_", x).strip("_")


def clean_text(x):
    x = "" if x is None else str(x)
    x = re.sub(r"<br\s*/?>", "\n", x, flags=re.I)
    x = re.sub(r"<[^>]+>", "", x)
    x = x.replace("\\_", "_").replace("\\|", "|")
    x = html.unescape(x)
    return re.sub(r"\n{3,}", "\n\n", x).strip()


def safe_text(x):
    return "" if pd.isna(x) else str(x).strip()


def text_contains(text, patterns):
    t = norm_name(clean_text(text))
    return any(norm_name(p) in t for p in patterns)


def first_existing(df, aliases, required=False):
    mapping = {norm_name(c): c for c in df.columns}
    for alias in aliases:
        if norm_name(alias) in mapping:
            return mapping[norm_name(alias)]
    if required:
        raise KeyError(f"No encontré ninguna de estas columnas: {aliases}")
    return None


def normalize_deal_id(series):
    s = series.astype(str).str.strip().str.replace(r"\.0$", "", regex=True)
    return s.replace({"nan": "", "None": "", "<NA>": ""})


def metric_card(label, value, sub="", color="#667085"):
    st.markdown(
        f"""
        <div class="metric-shell">
          <div class="metric-label"><span class="dot" style="background:{color};"></span>{html.escape(str(label))}</div>
          <div class="metric-value">{html.escape(str(value))}</div>
          <div class="metric-sub">{html.escape(str(sub)) if sub else ""}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def quote_box(text, color="#98A2B3"):
    if safe_text(text):
        st.markdown(
            f'<div class="quote-box" style="border-left-color:{color};">{html.escape(str(text))}</div>',
            unsafe_allow_html=True,
        )


# ---------- privacidad ----------

PII_COLUMN_ALIASES = [
    "Nombre completo", "Nombre", "Full Name", "full_name",
    "deal_name", "Deal_Name", "account_name", "Account_Name",
    "Empresa", "Correo electrónico", "Correo", "email", "email_norm",
    "Móvil", "Movil", "mobile", "phone", "telefono", "teléfono",
    "Sitio web", "website",
]

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)")
URL_RE = re.compile(r"(?:https?://|www\.)\S+", re.I)


def collect_sensitive_values(*dfs):
    values = set()
    for df in dfs:
        if df is None or df.empty:
            continue
        mapping = {norm_name(c): c for c in df.columns}
        for alias in PII_COLUMN_ALIASES:
            key = norm_name(alias)
            if key not in mapping:
                continue
            for raw in df[mapping[key]].astype(str).tolist():
                val = clean_text(raw).strip()
                if val and val.lower() not in {"nan","none","sin dato","n/a"} and len(val) >= 4:
                    values.add(val)
    return sorted(values, key=len, reverse=True)


def redact_text(text, sensitive_values):
    t = clean_text(text)
    if not t:
        return ""
    t = EMAIL_RE.sub("[EMAIL REDACTADO]", t)
    t = PHONE_RE.sub("[TELÉFONO REDACTADO]", t)
    t = URL_RE.sub("[URL REDACTADA]", t)
    for value in sensitive_values:
        try:
            t = re.sub(re.escape(value), "[DATO REDACTADO]", t, flags=re.I)
        except re.error:
            pass
    t = re.sub(r"\b\d{12,}\b", "[ID REDACTADO]", t)
    return t.strip()


# ---------- Google Sheets público ----------

def public_csv_url(spreadsheet_id, gid):
    return f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}/export?format=csv&gid={gid}"


@st.cache_data(ttl=300, show_spinner=False)
def load_public_sheet(spreadsheet_id, gid):
    response = requests.get(public_csv_url(spreadsheet_id, gid), timeout=30)
    response.raise_for_status()
    return pd.read_csv(StringIO(response.text), dtype=str, keep_default_na=False)


def load_all_sources():
    cfg = st.secrets["google_sheets"]
    sid = cfg["spreadsheet_id"]
    return (
        load_public_sheet(sid, cfg["leads_gid"]),
        load_public_sheet(sid, cfg["sales_gid"]),
        load_public_sheet(sid, cfg["notes_gid"]),
        load_public_sheet(sid, cfg["conversations_gid"]),
    )


# ---------- preparación ----------

def prepare_sources(leads, sales, notes, conversations):
    lead_deal_col = first_existing(leads, ["Id_Oportunidad", "deal_id", "Deal ID"], required=True)
    sales_deal_col = first_existing(sales, ["deal_id", "Deal ID", "Id_Oportunidad"], required=True)
    notes_deal_col = first_existing(notes, ["deal_id", "Deal ID", "Id_Oportunidad"], required=True)
    conv_deal_col = first_existing(conversations, ["deal_id", "Deal ID", "Id_Oportunidad"], required=True)

    for df, col in [(leads,lead_deal_col),(sales,sales_deal_col),(notes,notes_deal_col),(conversations,conv_deal_col)]:
        df["deal_id"] = normalize_deal_id(df[col])

    leads = leads[leads["deal_id"].ne("")].drop_duplicates("deal_id", keep="last")
    sales = sales[sales["deal_id"].ne("")].drop_duplicates("deal_id", keep="last")
    notes = notes[notes["deal_id"].ne("")]
    conversations = conversations[conversations["deal_id"].ne("")]
    return leads, sales, notes, conversations


def build_sales_notes(notes):
    creator_col = first_existing(notes, ["created_by_name", "created by name", "creado_por"])
    content_col = first_existing(notes, ["note_content", "content", "contenido_nota"])
    created_col = first_existing(notes, ["note_created_time", "created_time", "fecha_nota"])

    n = notes.copy()
    if creator_col:
        creators = n[creator_col].astype(str).str.lower()
        n = n[creators.apply(lambda x: any(name in x for name in SALES_USERS))].copy()

    if content_col is None:
        return pd.DataFrame(columns=["deal_id","sales_notes_text","num_sales_notes"])

    def aggregate(group):
        if created_col:
            group = group.sort_values(created_col)
        rows = [clean_text(x) for x in group[content_col].tolist() if clean_text(x)]
        return pd.Series({"sales_notes_text":"\n\n---\n\n".join(rows),"num_sales_notes":len(rows)})

    if n.empty:
        return pd.DataFrame(columns=["deal_id","sales_notes_text","num_sales_notes"])

    return n.groupby("deal_id", dropna=False).apply(aggregate).reset_index()


def build_conversations(conversations):
    content_col = first_existing(conversations, ["conversation_clean","conversation_text","conversation"])
    if content_col is None:
        return pd.DataFrame(columns=["deal_id","conversation_text_all","num_conversations"])

    def aggregate(group):
        rows = [clean_text(x) for x in group[content_col].tolist() if clean_text(x)]
        return pd.Series({"conversation_text_all":"\n\n---\n\n".join(rows),"num_conversations":len(rows)})

    return conversations.groupby("deal_id", dropna=False).apply(aggregate).reset_index()


def build_master(leads, sales, notes, conversations):
    master = leads.merge(sales, on="deal_id", how="left", suffixes=("", "_sales"))
    master = master.merge(build_sales_notes(notes), on="deal_id", how="left")
    master = master.merge(build_conversations(conversations), on="deal_id", how="left")
    for c in ["sales_notes_text","conversation_text_all"]:
        if c not in master:
            master[c] = ""
        master[c] = master[c].fillna("")
    return master


def map_fields(df):
    return {
        "fase": first_existing(df, ["Fase","Stage"]),
        "motivo_perf": first_existing(df, ["Motivo (Perf)","Motivo Perf","motivo_perf"]),
        "estatus_cierre": first_existing(df, ["Estatus de cierre","estatus_cierre"]),
        "ad_value": first_existing(df, ["ad_value"]),
        "tamano": first_existing(df, ["Tamano_RevOps_Final","Tamaño_RevOps_Final","Tamaño de la empresa","tamano"]),
        "estado": first_existing(df, ["Estado/Provincia","Estado","state","Provincia"]),
        "necesidad": first_existing(df, ["¿Qué necesidad tiene tu empresa?","Que necesidad tiene tu empresa","necesidad"]),
        "decision": first_existing(df, ["¿A quiénes hay que involucrar para tomar la decis?","A quienes hay que involucrar para tomar la decis","decision"]),
        "presupuesto": first_existing(df, ["¿Qué presupuesto mensual estás considerando?","Que presupuesto mensual estas considerando","presupuesto"]),
        "cotizacion": first_existing(df, ["cotizacion_enviada","Cotización enviada","cotizacion"]),
        "promo_condiciones": first_existing(df, ["promo_condiciones_pago","Promo o condiciones de pago"]),
        "objetivo_buscado": first_existing(df, ["objetivo_buscado","Qué objetivo buscas lograr resolviendo esto"]),
    }


def col_or_blank(df, col):
    return df[col].fillna("").astype(str) if col and col in df.columns else pd.Series("", index=df.index)


def filter_lost_cases(df, fields):
    fase = col_or_blank(df, fields["fase"])

    # Regla exacta solicitada:
    # incluir únicamente casos cuya columna Fase contenga
    # "Descartado" o "Cierre Perdido".
    mask = fase.str.contains(
        r"Descartado|Cierre\s*Perdido",
        case=False,
        na=False,
        regex=True,
    )

    return df[mask].copy()


# ---------- clasificación ----------

def classify_row(row, fields):
    parts = []
    for key in ["motivo_perf", "promo_condiciones", "objetivo_buscado"]:
        col = fields.get(key)
        if col:
            parts.append(clean_text(row.get(col, "")))

    parts += [
        clean_text(row.get("sales_notes_text", "")),
        clean_text(row.get("conversation_text_all", "")),
    ]
    all_text = "\n".join(parts)

    # CASI CIERRE: sólo cuando existe paso explícito de contratación/pago.
    if text_contains(
        all_text,
        [
            "liga de pago",
            "link de pago",
            "iniciaria con el plan",
            "iniciaría con el plan",
            "confirmo que iniciaria",
            "confirmó que iniciaría",
            "procedia para contratar",
            "procedía para contratar",
        ],
    ):
        return "Casi cierre"

    # PROVEEDOR / COMPETENCIA explícita
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

    # MISMATCH explícito: la necesidad final corresponde claramente a otro servicio.
    if text_contains(
        all_text,
        [
            "comprobante de domicilio",
            "planes moviles",
            "planes móviles",
            "telefonia movil con internet",
            "telefonía móvil con internet",
            "linea telefonica unicamente",
            "línea telefónica únicamente",
            "quiere utilizar su numero movil como principal",
            "quiere utilizar su número móvil como principal",
        ],
    ):
        return "Mismatch explícito"

    # PROYECTO INMADURO / EXPLORACIÓN:
    # incluye negocio todavía en constitución/documentación y proyectos sin aprobación.
    if text_contains(
        all_text,
        [
            "curioseando",
            "solo estoy investigando",
            "sólo estoy investigando",
            "no es un proyecto",
            "proyecto no listo",
            "no saben si en este ano o el proximo",
            "no saben si en este año o el próximo",
            "falta de definicion de presupuesto",
            "falta de definición de presupuesto",
            "sin aprobacion final",
            "sin aprobación final",
            "sin documentos de validacion",
            "sin documentos de validación",
            "aun no tiene los documentos",
            "aún no tiene los documentos",
            "empresa se esta constituyendo",
            "empresa se está constituyendo",
            "acaba de abrir",
        ],
    ):
        return "Proyecto inmaduro / exploración"

    # GHOSTING POST-AVANCE:
    # propuesta/demo/cotización + no respuesta/no-show.
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
            "se manda propuesta",
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

    # En este corte original todos los descartes restantes son pérdidas
    # de contacto registradas en CRM, por lo que no usamos categoría indefinida.
    return "Ghosting post-propuesta/demo"


def classify_all(df, fields):
    out = df.copy()
    out["clasificacion"] = out.apply(lambda r: classify_row(r, fields), axis=1)
    return out


def extract_evidence(row, fields, category, sensitive_values):
    sources = []

    for label, key in [("Motivo CRM","motivo_perf"),("Proceso de venta","promo_condiciones")]:
        col = fields.get(key)
        if col:
            val = clean_text(row.get(col,""))
            if val:
                sources.append((label, redact_text(val, sensitive_values)))

    notes = clean_text(row.get("sales_notes_text",""))
    if notes:
        keywords = {
            "Casi cierre":["liga de pago","contratar","plan de 200","iniciaria","iniciaría"],
            "Ghosting post-propuesta/demo":["no responde","no se conect","propuesta","videollamada","demo"],
            "Mismatch explícito":["comprobante","planes moviles","planes móviles","linea telefonica","línea telefónica","numero movil","número móvil"],
            "Proyecto inmaduro / exploración":["no es un proyecto","curioseando","investigando","luz verde"],
            "Requisito / documentación":["document","validacion","validación"],
            "Necesidad ampliada + no respuesta":["automatic","automat","agente virtual","no responde"],
            "Proveedor actual / competencia":["proveedor","plataforma","otro servicio"],
        }.get(category, [])

        chunks = [x.strip() for x in re.split(r"\n\n---\n\n|\n", notes) if x.strip()]
        picked = []
        for ch in chunks:
            if any(norm_name(k) in norm_name(ch) for k in keywords):
                picked.append(ch)
            if len(picked) >= 3:
                break
        sources += [("Nota de ventas", redact_text(x, sensitive_values)) for x in picked]

    seen, clean_sources = set(), []
    for label, text in sources:
        key = norm_name(text)
        if text and key not in seen:
            seen.add(key)
            clean_sources.append((label,text))
    return clean_sources[:5]


# ---------- carga ----------

try:
    with st.spinner("Leyendo Google Sheets..."):
        leads, sales, notes, conversations = load_all_sources()
        sensitive_values = collect_sensitive_values(leads, sales, notes, conversations)
        leads, sales, notes, conversations = prepare_sources(leads, sales, notes, conversations)
        master = build_master(leads, sales, notes, conversations)
        fields = map_fields(master)
        lost = classify_all(filter_lost_cases(master, fields), fields)
except Exception as e:
    st.error("No fue posible cargar la información desde Google Sheets.")
    st.caption("Revisa acceso público e IDs/GIDs.")
    st.exception(e)
    st.stop()


def display_col(name, default="Sin dato", redact=False):
    col = fields.get(name)
    if not col:
        return pd.Series(default, index=lost.index)
    s = lost[col].fillna("").astype(str).str.strip().replace("", default)
    if redact:
        s = s.apply(lambda x: redact_text(x, sensitive_values))
    return s


lost["ad_value_display"] = display_col("ad_value")
lost["tamano_display"] = display_col("tamano")
lost["estado_display"] = display_col("estado")
lost["necesidad_display"] = display_col("necesidad", redact=True)
lost["decision_display"] = display_col("decision", redact=True)
lost["presupuesto_display"] = display_col("presupuesto", redact=True)
lost["cotizacion_display"] = display_col("cotizacion", redact=True)
lost["motivo_display"] = display_col("motivo_perf", redact=True)
lost["es_micro"] = lost["tamano_display"].str.contains("Microempresa", case=False, na=False)


# ---------- diagnóstico de carga ----------
with st.sidebar.expander("Diagnóstico de carga"):
    st.write("Leads:", len(leads))
    st.write("Proceso venta:", len(sales))
    st.write("Notas:", len(notes))
    st.write("Conversaciones:", len(conversations))
    st.write("Master después del cruce:", len(master))
    st.write("Casos perdidos detectados:", len(lost))

    st.markdown("**Columnas detectadas**")
    st.json({
        "fase": fields.get("fase"),
        "motivo_perf": fields.get("motivo_perf"),
        "estatus_cierre": fields.get("estatus_cierre"),
        "ad_value": fields.get("ad_value"),
        "tamano": fields.get("tamano"),
        "estado": fields.get("estado"),
        "necesidad": fields.get("necesidad"),
        "decision": fields.get("decision"),
        "cotizacion": fields.get("cotizacion"),
    })

    if fields.get("fase"):
        st.markdown("**Valores de Fase (muestra)**")
        vals = (
            master[fields["fase"]]
            .fillna("")
            .astype(str)
            .value_counts()
            .head(15)
            .to_dict()
        )
        st.json(vals)

    if fields.get("motivo_perf"):
        st.markdown("**Motivos con 'Descartado'**")
        motivos = master[
            master[fields["motivo_perf"]]
            .fillna("")
            .astype(str)
            .str.contains("Descartado", case=False, na=False)
        ]
        st.write("Filas:", len(motivos))



# ---------- categorías descriptivas de necesidad ----------

def classify_need_text(text):
    t = norm_name(clean_text(text))

    if not t or t == "sin_dato":
        return "Sin dato"

    # Casos de uso específicos antes que categorías generales.
    if any(k in t for k in ["planes_moviles", "telefonia_movil", "internet_y_llamadas"]):
        return "Telefonía móvil / planes"

    if any(k in t for k in ["comprobante_de_domicilio", "recibo"]):
        return "Línea tradicional / comprobante"

    if any(k in t for k in ["inteligencia_artificial", "agente_virtual", "automat", "responder_en_automatico"]):
        return "Automatización / IA"

    if any(k in t for k in ["whatsapp", "mensajes", "redes", "centralizar", "unificar"]):
        return "Mensajes / WhatsApp / centralización"

    if any(k in t for k in ["call_center", "contact_center", "mesa_de_ayuda"]):
        return "Call center"

    if any(k in t for k in ["menu_de_opciones", "extensiones", "conmutador", "canalizar", "transferencia_de_llamadas"]):
        return "Conmutador / extensiones"

    if any(k in t for k in ["numero_empresarial", "linea_empresarial", "numero_virtual"]):
        return "Número empresarial"

    if any(k in t for k in ["celular", "computadora", "recibir_llamadas"]):
        return "Recibir llamadas en celular/computadora"

    if any(k in t for k in ["imagen_profesional", "sonar_profesional"]):
        return "Imagen profesional"

    return "Otro caso de uso"


def sales_request_text(row):
    pieces = []

    # Primero campos estructurados de proceso de venta.
    for key in ["objetivo_buscado", "promo_condiciones"]:
        col = fields.get(key)
        if col:
            val = clean_text(row.get(col, ""))
            if val:
                pieces.append(val)

    # Después notas de ventas, que reflejan mejor qué terminó solicitando.
    notes = clean_text(row.get("sales_notes_text", ""))
    if notes:
        pieces.append(notes)

    return "\n".join(pieces)


lost["necesidad_categoria"] = lost["necesidad_display"].apply(classify_need_text)
lost["solicitud_ventas_categoria"] = lost.apply(
    lambda r: classify_need_text(sales_request_text(r)),
    axis=1,
)


# ---------- UI ----------

st.title("SQL perdidos")
st.caption("SQL Fuente: Meta, 10 jul - 10 ago")

if lost.empty:
    st.error(
        "No se detectaron oportunidades perdidas con las columnas actuales. "
        "Abre 'Diagnóstico de carga' en la barra lateral para revisar qué hojas y columnas llegaron desde Google Sheets."
    )

view = lost.copy()

tabs = st.tabs(["1 · Descriptivos","2 · Patrones e insights","3 · Hipótesis"])


with tabs[0]:
    if view.empty:
        st.warning("No hay casos con los filtros seleccionados.")
    else:
        total = len(view)
        micro = int(view["es_micro"].sum())
        ghost = int((view["clasificacion"]=="Ghosting post-propuesta/demo").sum())
        mismatch = int((view["clasificacion"]=="Mismatch explícito").sum())
        near = int((view["clasificacion"]=="Casi cierre").sum())

        c1,c2,c3,c4,c5 = st.columns(5)
        with c1: metric_card("Casos", total, "deal_id únicos", COLORS["ink"])
        with c2: metric_card("Microempresa", micro, f"{round(100*micro/total)}% del corte", COLORS["orange"])
        with c3: metric_card("Ghosting post-avance", ghost, "regla estricta", COLORS["red"])
        with c4: metric_card("Mismatch explícito", mismatch, "evidencia directa", COLORS["yellow"])
        with c5: metric_card("Casi cierre", near, "contratación/pago explícito", COLORS["green"])

        counts = view["clasificacion"].value_counts().rename_axis("Clasificación").reset_index(name="Casos")
        fig = px.bar(counts, x="Casos", y="Clasificación", orientation="h", color="Clasificación", color_discrete_map=CATEGORY_COLORS, text="Casos")
        fig.update_layout(height=420, showlegend=False, xaxis_title="Casos", yaxis_title="")
        st.plotly_chart(fig, use_container_width=True)

        c1,c2 = st.columns(2)
        with c1:
            tmp = view["tamano_display"].value_counts().rename_axis("Tamaño").reset_index(name="Casos")
            st.plotly_chart(px.bar(tmp,x="Casos",y="Tamaño",orientation="h",text="Casos"), use_container_width=True)
        with c2:
            tmp = view["estado_display"].value_counts().rename_axis("Estado").reset_index(name="Casos")
            st.plotly_chart(px.bar(tmp,x="Casos",y="Estado",orientation="h",text="Casos"), use_container_width=True)

        st.markdown("### Oferta × clasificación")
        matrix = view.groupby(["ad_value_display","clasificacion"]).size().reset_index(name="Casos")
        fig = px.bar(matrix, x="ad_value_display", y="Casos", color="clasificacion", color_discrete_map=CATEGORY_COLORS, barmode="stack")
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Necesidad declarada vs. solicitud observada en ventas")

        c1, c2 = st.columns(2)

        with c1:
            need_counts = (
                view["necesidad_categoria"]
                .value_counts()
                .rename_axis("Necesidad declarada")
                .reset_index(name="Casos")
            )
            fig = px.bar(
                need_counts,
                x="Casos",
                y="Necesidad declarada",
                orientation="h",
                text="Casos",
            )
            fig.update_layout(
                height=390,
                showlegend=False,
                xaxis_title="Casos",
                yaxis_title="",
            )
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            sales_counts = (
                view["solicitud_ventas_categoria"]
                .value_counts()
                .rename_axis("Solicitud en ventas")
                .reset_index(name="Casos")
            )
            fig = px.bar(
                sales_counts,
                x="Casos",
                y="Solicitud en ventas",
                orientation="h",
                text="Casos",
            )
            fig.update_layout(
                height=390,
                showlegend=False,
                xaxis_title="Casos",
                yaxis_title="",
            )
            st.plotly_chart(fig, use_container_width=True)

        st.caption(
            "Izquierda: respuesta inicial del lead. Derecha: necesidad/solicitud que aparece posteriormente en el proceso de venta."
        )

        st.markdown("### Presupuesto mensual declarado")
        budget_counts = (
            view["presupuesto_display"]
            .value_counts()
            .rename_axis("Presupuesto")
            .reset_index(name="Casos")
        )
        fig = px.bar(
            budget_counts,
            x="Presupuesto",
            y="Casos",
            text="Casos",
        )
        fig.update_layout(
            height=360,
            showlegend=False,
            xaxis_title="Presupuesto mensual",
            yaxis_title="Casos",
        )
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Casos")
        st.dataframe(
            view[[
                "deal_id","ad_value_display","tamano_display","estado_display",
                "necesidad_display","decision_display","presupuesto_display",
                "cotizacion_display","clasificacion","motivo_display"
            ]],
            use_container_width=True,
            hide_index=True,
        )


with tabs[1]:
    st.markdown("## Casos que requieren revisión")

    st.markdown("### 1. Casi cierre")
    subset = view[view["clasificacion"]=="Casi cierre"]
    if subset.empty:
        st.caption("Sin casos con los filtros actuales.")
    else:
        for _, row in subset.iterrows():
            st.markdown(f"**deal_id:** `{row['deal_id']}`")
            st.caption(row["ad_value_display"])
            for label,text in extract_evidence(row,fields,row["clasificacion"],sensitive_values):
                st.caption(label)
                quote_box(text,COLORS["green"])

    st.markdown("---")
    st.markdown("### 2. Necesidad inicial vs necesidad revelada")
    subset = view[view["clasificacion"].isin(["Mismatch explícito","Necesidad ampliada + no respuesta"])]
    if subset.empty:
        st.caption("Sin casos con los filtros actuales.")
    else:
        for _, row in subset.iterrows():
            color = CATEGORY_COLORS[row["clasificacion"]]
            st.markdown(f"**deal_id:** `{row['deal_id']}` · **{row['clasificacion']}**")
            st.write(f"Oferta: {row['ad_value_display']}")
            st.write(f"Necesidad de entrada: {row['necesidad_display']}")
            for label,text in extract_evidence(row,fields,row["clasificacion"],sensitive_values):
                st.caption(label)
                quote_box(text,color)

    st.markdown("---")
    st.markdown("### 3. Casos atípicos / extremos")
    subset = view[view["clasificacion"].isin(["Mismatch explícito","Requisito / documentación","Proveedor actual / competencia"])]
    if subset.empty:
        st.caption("Sin casos con los filtros actuales.")
    else:
        for _, row in subset.iterrows():
            with st.expander(f"{row['deal_id']} · {row['clasificacion']}"):
                st.write("Necesidad:", row["necesidad_display"])
                st.write("Motivo:", row["motivo_display"])
                for label,text in extract_evidence(row,fields,row["clasificacion"],sensitive_values):
                    st.caption(label)
                    quote_box(text,CATEGORY_COLORS[row["clasificacion"]])

    st.markdown("---")
    st.markdown("## Explorador por deal_id")
    if not view.empty:
        selected = st.selectbox("Deal", view["deal_id"].tolist())
        row = view[view["deal_id"]==selected].iloc[0]
        color = CATEGORY_COLORS.get(row["clasificacion"], COLORS["gray"])

        c1,c2,c3,c4 = st.columns(4)
        with c1: metric_card("Clasificación", row["clasificacion"], "", color)
        with c2: metric_card("Tamaño", row["tamano_display"], "", COLORS["orange"])
        with c3: metric_card("Cotización", row["cotizacion_display"], "", COLORS["blue"])
        with c4: metric_card("Deal", row["deal_id"], "", COLORS["purple"])

        st.write("**Oferta:**", row["ad_value_display"])
        st.write("**Necesidad registrada:**", row["necesidad_display"])
        st.write("**Motivo CRM:**", row["motivo_display"])

        for label,text in extract_evidence(row,fields,row["clasificacion"],sensitive_values):
            st.caption(label)
            quote_box(text,color)


with tabs[2]:
    st.markdown("## Hipótesis")
    st.caption("Señales del corte y acciones propuestas para validar.")

    c1, c2 = st.columns(2)

    with c1:
        st.markdown(
            f"""
            <div class="hypothesis">
                <b><span class="dot" style="background:{COLORS['orange']};"></span>
                H1 · Conmutador virtual: caso de uso muy abierto</b><br><br>
                La oferta puede agrupar necesidades distintas bajo una misma promesa.<br><br>
                <b>Acción:</b> modificar copys hacia casos de uso específicos y menos abiertos.
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            f"""
            <div class="hypothesis">
                <b><span class="dot" style="background:{COLORS['red']};"></span>
                H2 · Fuga comercial después de propuesta/demo</b><br><br>
                Parte de los casos pierde contacto después de una señal clara de avance comercial.<br><br>
                <b>Acción:</b> incentivar el cierre y medir actividad post-propuesta/demo con tasas de respuesta.
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")

    c3, c4 = st.columns(2)

    with c3:
        st.markdown(
            f"""
            <div class="hypothesis">
                <b><span class="dot" style="background:{COLORS['yellow']};"></span>
                H3 · Madurez del proyecto + riesgo de fraude</b><br><br>
                Algunos casos llegan sin proyecto listo, documentación o condiciones suficientes para avanzar.<br><br>
                <b>Acción:</b> investigación temprana para detectar posibles fraudes o inmadurez del proyecto antes de profundizar el proceso comercial.
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c4:
        st.markdown(
            f"""
            <div class="hypothesis">
                <b><span class="dot" style="background:{COLORS['blue']};"></span>
                H4 · Expansión de necesidad</b><br><br>
                En algunos casos la necesidad inicial se amplía durante ventas hacia mensajes, automatización u otros alcances.<br><br>
                <b>Acción:</b> escalar formatos como el video 209 y probar anuncios con capacidad de expandir la necesidad.
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("---")
st.caption("Zoho CRM-Notas")
