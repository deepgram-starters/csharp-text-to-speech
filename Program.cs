/**
 * C# Text-to-Speech Starter - Backend Server
 *
 * This is a minimal API server that provides a text-to-speech API endpoint
 * powered by Deepgram's Text-to-Speech service. It's designed to be easily
 * modified and extended for your own projects.
 *
 * Key Features:
 * - Contract-compliant API endpoint: POST /api/text-to-speech
 * - Accepts text in body and model as query parameter
 * - Returns binary audio data (audio/mpeg)
 * - JWT session auth with rate limiting (production only)
 * - CORS enabled for frontend communication
 * - Pure API server (frontend served separately)
 */

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Deepgram;
using Deepgram.Models.Speak.v1.REST;
using Microsoft.IdentityModel.Tokens;
using Tomlyn;
using Tomlyn.Model;
using HttpResults = Microsoft.AspNetCore.Http.Results;

// ============================================================================
// ENVIRONMENT LOADING
// ============================================================================

DotNetEnv.Env.Load();

// ============================================================================
// CONFIGURATION - Customize these values for your needs
// ============================================================================

/// Default text-to-speech model to use when none is specified
/// Options: "aura-2-thalia-en", "aura-2-theia-en", "aura-2-andromeda-en", etc.
/// See: https://developers.deepgram.com/docs/text-to-speech-models
const string DefaultModel = "aura-2-thalia-en";

var port = int.TryParse(Environment.GetEnvironmentVariable("PORT"), out var p) ? p : 8081;
var host = Environment.GetEnvironmentVariable("HOST") ?? "0.0.0.0";

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

var sessionSecretEnv = Environment.GetEnvironmentVariable("SESSION_SECRET");
var sessionSecret = sessionSecretEnv ?? Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
var sessionSecretKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(sessionSecret));

const int JwtExpirySeconds = 3600; // 1 hour

string CreateSessionToken()
{
    var handler = new JwtSecurityTokenHandler();
    var descriptor = new SecurityTokenDescriptor
    {
        Expires = DateTime.UtcNow.AddSeconds(JwtExpirySeconds),
        SigningCredentials = new SigningCredentials(sessionSecretKey, SecurityAlgorithms.HmacSha256Signature),
    };
    var token = handler.CreateToken(descriptor);
    return handler.WriteToken(token);
}

bool ValidateSessionToken(string token)
{
    try
    {
        var handler = new JwtSecurityTokenHandler();
        handler.ValidateToken(token, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = sessionSecretKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero,
        }, out _);
        return true;
    }
    catch
    {
        return false;
    }
}

// ============================================================================
// API KEY LOADING - Load Deepgram API key from .env
// ============================================================================

static string LoadApiKey()
{
    var apiKey = Environment.GetEnvironmentVariable("DEEPGRAM_API_KEY");

    if (string.IsNullOrEmpty(apiKey))
    {
        Console.Error.WriteLine("\n❌ ERROR: Deepgram API key not found!\n");
        Console.Error.WriteLine("Please set your API key using one of these methods:\n");
        Console.Error.WriteLine("1. Create a .env file (recommended):");
        Console.Error.WriteLine("   DEEPGRAM_API_KEY=your_api_key_here\n");
        Console.Error.WriteLine("2. Environment variable:");
        Console.Error.WriteLine("   export DEEPGRAM_API_KEY=your_api_key_here\n");
        Console.Error.WriteLine("Get your API key at: https://console.deepgram.com\n");
        Environment.Exit(1);
    }

    return apiKey;
}

var apiKey = LoadApiKey();

// ============================================================================
// SETUP - Initialize ASP.NET Minimal API, Deepgram, and middleware
// ============================================================================

Library.Initialize();
var deepgramClient = ClientFactory.CreateSpeakRESTClient(apiKey);

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://{host}:{port}");

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

var app = builder.Build();
app.UseCors();

// ============================================================================
// HELPER FUNCTIONS - Modular logic for easier understanding and testing
// ============================================================================

/// Validates that text was provided in the request
static bool ValidateTextInput(string? text)
{
    return !string.IsNullOrWhiteSpace(text);
}

/// Formats error responses in a consistent structure matching the contract
static (int statusCode, object body) FormatErrorResponse(
    string message, int statusCode = 500, string? errorCode = null, string? originalError = null)
{
    // Map to contract error codes
    var contractCode = errorCode;
    if (contractCode == null)
    {
        if (statusCode == 400)
        {
            var lowerMsg = message.ToLowerInvariant();
            if (lowerMsg.Contains("empty")) contractCode = "EMPTY_TEXT";
            else if (lowerMsg.Contains("model")) contractCode = "MODEL_NOT_FOUND";
            else if (lowerMsg.Contains("long")) contractCode = "TEXT_TOO_LONG";
            else contractCode = "INVALID_TEXT";
        }
        else
        {
            contractCode = "INVALID_TEXT";
        }
    }

    return (statusCode, new Dictionary<string, object?>
    {
        ["error"] = new Dictionary<string, object?>
        {
            ["type"] = statusCode == 400 ? "ValidationError" : "GenerationError",
            ["code"] = contractCode,
            ["message"] = message,
            ["details"] = new Dictionary<string, object?>
            {
                ["originalError"] = originalError ?? message,
            },
        },
    });
}

// ============================================================================
// SESSION ROUTES - Auth endpoints (unprotected)
// ============================================================================

app.MapGet("/api/session", () =>
{
    var token = CreateSessionToken();
    return HttpResults.Json(new Dictionary<string, string> { ["token"] = token });
});

// ============================================================================
// API ROUTES
// ============================================================================

/// POST /api/text-to-speech
///
/// Contract-compliant text-to-speech endpoint.
/// Accepts:
/// - Query parameter: model (optional)
/// - Body: JSON with text field (required)
///
/// Returns:
/// - Success (200): Binary audio data (audio/mpeg)
/// - Error (4XX): JSON error response matching contract format
app.MapPost("/api/text-to-speech", async (HttpRequest request) =>
{
    // Validate JWT session token
    var authHeader = request.Headers.Authorization.FirstOrDefault() ?? "";
    if (!authHeader.StartsWith("Bearer "))
    {
        return HttpResults.Json(new Dictionary<string, object>
        {
            ["error"] = new Dictionary<string, string>
            {
                ["type"] = "AuthenticationError",
                ["code"] = "MISSING_TOKEN",
                ["message"] = "Authorization header with Bearer token is required",
            }
        }, statusCode: 401);
    }
    if (!ValidateSessionToken(authHeader[7..]))
    {
        return HttpResults.Json(new Dictionary<string, object>
        {
            ["error"] = new Dictionary<string, string>
            {
                ["type"] = "AuthenticationError",
                ["code"] = "INVALID_TOKEN",
                ["message"] = "Invalid or expired session token",
            }
        }, statusCode: 401);
    }

    try
    {
        // Get model from query parameter
        var model = request.Query["model"].FirstOrDefault() ?? DefaultModel;

        // Read JSON body
        var body = await request.ReadFromJsonAsync<Dictionary<string, string>>();
        var text = body?.GetValueOrDefault("text");

        // Validate input - text is required
        if (text == null)
        {
            var (errCode, errBody) = FormatErrorResponse(
                "Text parameter is required", 400, "EMPTY_TEXT");
            return HttpResults.Json(errBody, statusCode: errCode);
        }

        if (!ValidateTextInput(text))
        {
            var (errCode, errBody) = FormatErrorResponse(
                "Text must be a non-empty string", 400, "EMPTY_TEXT");
            return HttpResults.Json(errBody, statusCode: errCode);
        }

        // Generate audio using Deepgram TTS API
        var schema = new SpeakSchema { Model = model };
        var response = await deepgramClient.ToStream(
            new TextSource(text), schema);

        if (response?.Stream == null)
        {
            throw new InvalidOperationException("No audio stream returned from Deepgram");
        }

        // Read stream to byte array
        using var ms = new MemoryStream();
        await response.Stream.CopyToAsync(ms);
        var audioBytes = ms.ToArray();

        // Return binary audio data
        return HttpResults.Bytes(audioBytes, contentType: "audio/mpeg");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Text-to-speech error: {ex}");

        var statusCode = 500;
        string? errorCode = null;
        var errorMsg = ex.Message.ToLowerInvariant();

        if (errorMsg.Contains("model") || errorMsg.Contains("not found"))
        {
            statusCode = 400;
            errorCode = "MODEL_NOT_FOUND";
        }
        else if (errorMsg.Contains("too long") || errorMsg.Contains("length") || errorMsg.Contains("limit"))
        {
            statusCode = 400;
            errorCode = "TEXT_TOO_LONG";
        }
        else if (errorMsg.Contains("invalid") || errorMsg.Contains("malformed"))
        {
            statusCode = 400;
            errorCode = "INVALID_TEXT";
        }

        var (errSc, errBd) = FormatErrorResponse(ex.Message, statusCode, errorCode, ex.ToString());
        return HttpResults.Json(errBd, statusCode: errSc);
    }
});

// Health check endpoint
app.MapGet("/health", () => HttpResults.Json(new { status = "ok", service = "text-to-speech" }));

/// GET /api/metadata
app.MapGet("/api/metadata", () =>
{
    try
    {
        var tomlPath = Path.Combine(Directory.GetCurrentDirectory(), "deepgram.toml");
        var tomlContent = File.ReadAllText(tomlPath);
        var tomlModel = Toml.ToModel(tomlContent);

        if (!tomlModel.ContainsKey("meta") || tomlModel["meta"] is not TomlTable metaTable)
        {
            return HttpResults.Json(new Dictionary<string, string>
            {
                ["error"] = "INTERNAL_SERVER_ERROR",
                ["message"] = "Missing [meta] section in deepgram.toml",
            }, statusCode: 500);
        }

        var meta = new Dictionary<string, object?>();
        foreach (var kvp in metaTable)
        {
            meta[kvp.Key] = kvp.Value;
        }

        return HttpResults.Json(meta);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error reading metadata: {ex}");
        return HttpResults.Json(new Dictionary<string, string>
        {
            ["error"] = "INTERNAL_SERVER_ERROR",
            ["message"] = "Failed to read metadata from deepgram.toml",
        }, statusCode: 500);
    }
});

// ============================================================================
// SERVER START
// ============================================================================

Console.WriteLine();
Console.WriteLine(new string('=', 70));
Console.WriteLine($"🚀 Backend API Server running at http://localhost:{port}");
Console.WriteLine($"📡 CORS enabled for all origins");
Console.WriteLine($"📡 GET  /api/session");
Console.WriteLine($"📡 POST /api/text-to-speech (auth required)");
Console.WriteLine($"📡 GET  /health");
Console.WriteLine($"📡 GET  /api/metadata");
Console.WriteLine(new string('=', 70));
Console.WriteLine();

app.Run();
