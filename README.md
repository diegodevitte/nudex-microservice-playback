# NUDEX Playback Service

Microservicio para generación de tokens efímeros de reproducción y streaming.

## 🚀 Stack

- **Go 1.22+** + **Gin Framework**
- **Redis** - Storage de tokens efímeros
- **JWT** - Tokens seguros
- **RabbitMQ** - Eventos de reproducción

## 📡 Endpoints

```
GET  /health                    # Health check
POST /playback/token           # Generar token de reproducción
GET  /playback/resolve/{token} # Resolver token a URL de video
POST /playback/start           # Iniciar reproducción (analytics)
```

## 🔧 Features

- ✅ Tokens JWT con TTL corto (1 hora)
- ✅ Cache Redis para tokens activos
- ✅ Analytics de reproducción
- ✅ Rate limiting por IP
- ✅ Eventos RabbitMQ
- ✅ URL signing para seguridad
