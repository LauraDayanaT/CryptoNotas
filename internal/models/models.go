package models

type PayloadEvento struct {
	IDEvento      string   `json:"id_evento"`
	Tipo          string   `json:"tipo"`
	Timestamp     string   `json:"timestamp"`
	ActorUID      string   `json:"actor_uid"`
	EstudianteUID string   `json:"estudiante_uid"`
	CursoUID      string   `json:"curso_uid"`
	NotaAnterior  *float64 `json:"nota_anterior,omitempty"`
	NotaNueva     float64  `json:"nota_nueva"`
}

type Evento struct {
	PayloadEvento
	HashPayload string `json:"hash_payload"`
}

type MetadatosLog struct {
	VersionEsquema  string `json:"version_esquema"`
	FechaGeneracion string `json:"fecha_generacion"`
	CantidadEventos int    `json:"cantidad_eventos"`
	SistemaOrigen   string `json:"sistema_origen"`
}

type Log struct {
	Metadatos MetadatosLog `json:"metadatos"`
	Eventos   []Evento     `json:"eventos"`
}

const (
	TipoRegistroNota     = "REGISTRO_NOTA"
	TipoModificacionNota = "MODIFICACION_NOTA"
)
