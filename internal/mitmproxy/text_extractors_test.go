package mitmproxy

import (
	"testing"

	"tap/internal/attestation"
)

func TestOpenAIChatConversationExtractor(t *testing.T) {
	extractor := mustTextExtractor(t, ExtractorOpenAIChatConversation)
	requestFields, err := extractor.ExtractRequest([]byte(`{
		"model":"gpt-test",
		"messages":[
			{"role":"system","content":"be concise"},
			{"role":"user","content":[{"type":"text","text":"hel"},{"type":"text","text":"lo"}]}
		]
	}`), "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	assertConversationFields(t, requestFields, `"gpt-test"`, `[{"role":"system","text":"be concise"},{"role":"user","text":"hello"}]`)

	responseFields, err := extractor.ExtractResponse([]byte(`{
		"choices":[{"message":{"role":"assistant","content":[{"type":"text","text":"wor"},{"type":"text","text":"ld"}]}}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	assertResponseMessages(t, responseFields, `[{"role":"assistant","text":"world"}]`)
}

func TestStreamingRequestFieldsNormalizeSupportedJSONProtocols(t *testing.T) {
	tests := []struct {
		name, extractor, path, body string
	}{
		{
			name:      "OpenAI Chat",
			extractor: ExtractorOpenAIChatConversation,
			path:      "/v1/chat/completions",
			body:      `{"model":"shared-model","messages":[{"role":"user","content":"hello"}],"stream":true}`,
		},
		{
			name:      "OpenAI Responses",
			extractor: ExtractorOpenAIResponsesConversation,
			path:      "/v1/responses",
			body:      `{"model":"shared-model","input":"hello","stream":true}`,
		},
		{
			name:      "Anthropic Messages",
			extractor: ExtractorAnthropicMessagesConversation,
			path:      "/v1/messages",
			body:      `{"model":"shared-model","messages":[{"role":"user","content":"hello"}],"stream":true}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			extractor := mustTextExtractor(t, test.extractor)
			fields, err := extractor.ExtractRequest([]byte(test.body), test.path)
			if err != nil {
				t.Fatal(err)
			}
			fields, err = appendStreamingRequestField([]byte(test.body), fields)
			if err != nil {
				t.Fatal(err)
			}
			if len(fields) != 3 || fields[2].Name != "stream" || string(fields[2].Value) != "true" {
				t.Fatalf("unexpected streaming request fields: %#v", fields)
			}
		})
	}
}

func TestStreamingRequestFieldsRequireTrueBoolean(t *testing.T) {
	base := []attestation.Field{mustFieldForExtractor(t, "model", `"gpt-test"`)}
	for name, body := range map[string]string{
		"missing": `{}`,
		"false":   `{"stream":false}`,
		"string":  `{"stream":"true"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := appendStreamingRequestField([]byte(body), base); err == nil {
				t.Fatal("expected streaming request to be rejected")
			}
		})
	}
}

func TestConversationExtractorsNormalizeEquivalentProtocols(t *testing.T) {
	chat := mustTextExtractor(t, ExtractorOpenAIChatConversation)
	chatFields, err := chat.ExtractRequest([]byte(`{
		"model":"shared-model",
		"messages":[
			{"role":"system","content":"be concise"},
			{"role":"user","content":"hello"},
			{"role":"assistant","content":"hi"},
			{"role":"user","content":"explain signatures"}
		]
	}`), "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}

	anthropic := mustTextExtractor(t, ExtractorAnthropicMessagesConversation)
	anthropicFields, err := anthropic.ExtractRequest([]byte(`{
		"model":"shared-model",
		"system":[{"type":"text","text":"be "},{"type":"text","text":"concise"}],
		"messages":[
			{"role":"user","content":[{"type":"text","text":"hello"}]},
			{"role":"assistant","content":"hi"},
			{"role":"user","content":"explain signatures"}
		]
	}`), "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}

	responses := mustTextExtractor(t, ExtractorOpenAIResponsesConversation)
	responsesFields, err := responses.ExtractRequest([]byte(`{
		"model":"shared-model",
		"instructions":"be concise",
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]},
			{"type":"message","role":"assistant","content":"hi"},
			{"type":"message","role":"user","content":"explain signatures"}
		]
	}`), "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(anthropicFields[1].Value), string(chatFields[1].Value); got != want {
		t.Fatalf("Anthropic and Chat normalized messages differ:\nanthropic=%s\nchat=%s", got, want)
	}
	if got, want := string(responsesFields[1].Value), string(chatFields[1].Value); got != want {
		t.Fatalf("Responses and Chat normalized messages differ:\nresponses=%s\nchat=%s", got, want)
	}
}

func TestOpenAIResponsesConversationExtractorNormalizesStringInput(t *testing.T) {
	extractor := mustTextExtractor(t, ExtractorOpenAIResponsesConversation)
	stringFields, err := extractor.ExtractRequest([]byte(`{"model":"gpt-test","input":"hello"}`), "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	arrayFields, err := extractor.ExtractRequest([]byte(`{
		"model":"gpt-test",
		"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hel"},{"type":"input_text","text":"lo"}]}]
	}`), "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(stringFields[1].Value), string(arrayFields[1].Value); got != want {
		t.Fatalf("normalized inputs differ: string=%s array=%s", got, want)
	}
	assertConversationFields(t, arrayFields, `"gpt-test"`, `[{"role":"user","text":"hello"}]`)

	responseFields, err := extractor.ExtractResponse([]byte(`{
		"output":[
			{"type":"web_search_call","status":"completed"},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello "}]},
			{"type":"function_call","name":"ignored_by_text_profile"},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"world"}]}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	assertResponseMessages(t, responseFields, `[{"role":"assistant","text":"hello "},{"role":"assistant","text":"world"}]`)
}

func TestAnthropicConversationResponseMatchesOpenAIChat(t *testing.T) {
	anthropic := mustTextExtractor(t, ExtractorAnthropicMessagesConversation)
	anthropicFields, err := anthropic.ExtractResponse([]byte(`{
		"role":"assistant",
		"content":[{"type":"text","text":"hello"},{"type":"tool_use","name":"ignored"},{"type":"text","text":" world"}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	chat := mustTextExtractor(t, ExtractorOpenAIChatConversation)
	chatFields, err := chat.ExtractResponse([]byte(`{
		"choices":[{"message":{"role":"assistant","content":"hello world"}}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(anthropicFields[0].Value), string(chatFields[0].Value); got != want {
		t.Fatalf("normalized responses differ: anthropic=%s chat=%s", got, want)
	}
}

func TestBedrockConversationExtractors(t *testing.T) {
	invoke := mustTextExtractor(t, ExtractorBedrockInvokeConversation)
	requestFields, err := invoke.ExtractRequest([]byte(`{
		"anthropic_version":"bedrock-2023-05-31",
		"system":[{"text":"be concise"}],
		"messages":[{"role":"user","content":"hello"}]
	}`), "/model/us.anthropic.claude-test/invoke")
	if err != nil {
		t.Fatal(err)
	}
	assertConversationFields(t, requestFields, `"us.anthropic.claude-test"`, `[{"role":"system","text":"be concise"},{"role":"user","text":"hello"}]`)

	claudeFields, err := invoke.ExtractResponse([]byte(`{"role":"assistant","content":[{"type":"text","text":"claude"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	assertResponseMessages(t, claudeFields, `[{"role":"assistant","text":"claude"}]`)
	novaFields, err := invoke.ExtractResponse([]byte(`{"output":{"message":{"role":"assistant","content":[{"text":"nova"}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	assertResponseMessages(t, novaFields, `[{"role":"assistant","text":"nova"}]`)

	converse := mustTextExtractor(t, ExtractorBedrockConverseConversation)
	converseFields, err := converse.ExtractResponse([]byte(`{"output":{"message":{"role":"assistant","content":[{"text":"converse"}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	assertResponseMessages(t, converseFields, `[{"role":"assistant","text":"converse"}]`)
}

func TestConversationExtractorsFailClosedForAmbiguousContent(t *testing.T) {
	responses := mustTextExtractor(t, ExtractorOpenAIResponsesConversation)
	if _, err := responses.ExtractRequest([]byte(`{
		"model":"gpt-test",
		"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://example.com/a.png"}]}]
	}`), "/v1/responses"); err == nil {
		t.Fatal("expected non-text request input to be rejected")
	}
	if _, err := responses.ExtractRequest([]byte(`{
		"model":"gpt-test",
		"input":[{"type":"function_call_output","call_id":"call-1","output":"result"}]
	}`), "/v1/responses"); err == nil {
		t.Fatal("expected non-message input item to be rejected")
	}
	if _, err := responses.ExtractResponse([]byte(`{"output":[{"type":"function_call","name":"tool"}]}`)); err == nil {
		t.Fatal("expected response without final text to be rejected")
	}
	if _, err := responses.ExtractRequest([]byte(`{"model":"first","model":"second","input":"hello"}`), "/v1/responses"); err == nil {
		t.Fatal("expected duplicate JSON keys to be rejected")
	}

	chat := mustTextExtractor(t, ExtractorOpenAIChatConversation)
	if _, err := chat.ExtractRequest([]byte(`{
		"model":"gpt-test","messages":[{"role":"tool","content":"result"}]
	}`), "/v1/chat/completions"); err == nil {
		t.Fatal("expected tool role to be rejected")
	}
	if _, err := chat.ExtractRequest([]byte(`{
		"model":"gpt-test","messages":[{"role":"assistant","content":"calling","tool_calls":[{"id":"call-1"}]}]
	}`), "/v1/chat/completions"); err == nil {
		t.Fatal("expected request message tool calls to be rejected")
	}
	if _, err := chat.ExtractResponse([]byte(`{
		"choices":[{"message":{"content":"one"}},{"message":{"content":"two"}}]
	}`)); err == nil {
		t.Fatal("expected multiple choices to be rejected")
	}

	invoke := mustTextExtractor(t, ExtractorBedrockInvokeConversation)
	if _, err := invoke.ExtractResponse([]byte(`{
		"content":[{"type":"text","text":"ambiguous"}],
		"output":{"message":{"content":[{"text":"also ambiguous"}]}}
	}`)); err == nil {
		t.Fatal("expected ambiguous Bedrock response to be rejected")
	}
}

func mustTextExtractor(t *testing.T, name string) textExtractor {
	t.Helper()
	extractor, ok := lookupTextExtractor(name)
	if !ok {
		t.Fatalf("extractor %q not found", name)
	}
	return extractor
}

func mustFieldForExtractor(t *testing.T, name, value string) attestation.Field {
	t.Helper()
	field, err := attestation.NewField(name, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return field
}

func assertConversationFields(t *testing.T, fields []attestation.Field, model, messages string) {
	t.Helper()
	if len(fields) != 2 || fields[0].Name != "model" || fields[1].Name != "messages" {
		t.Fatalf("unexpected request fields: %#v", fields)
	}
	if got := string(fields[0].Value); got != model {
		t.Fatalf("model = %s, want %s", got, model)
	}
	if got := string(fields[1].Value); got != messages {
		t.Fatalf("messages = %s, want %s", got, messages)
	}
}

func assertResponseMessages(t *testing.T, fields []attestation.Field, messages string) {
	t.Helper()
	if len(fields) != 1 || fields[0].Name != "messages" {
		t.Fatalf("unexpected response fields: %#v", fields)
	}
	if got := string(fields[0].Value); got != messages {
		t.Fatalf("messages = %s, want %s", got, messages)
	}
}
