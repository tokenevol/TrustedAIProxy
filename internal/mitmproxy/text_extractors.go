package mitmproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	"tap/internal/attestation"
)

const (
	ExtractorOpenAIChatConversation        = "openai-chat-conversation-v1"
	ExtractorOpenAIResponsesConversation   = "openai-responses-conversation-v1"
	ExtractorAnthropicMessagesConversation = "anthropic-messages-conversation-v1"
	ExtractorBedrockInvokeConversation     = "bedrock-invoke-conversation-v1"
	ExtractorBedrockConverseConversation   = "bedrock-converse-conversation-v1"
)

type textExtractor interface {
	ExtractRequest(body []byte, requestPath string) ([]attestation.Field, error)
	ExtractResponse(body []byte) ([]attestation.Field, error)
}

type textExtractorFuncs struct {
	request  func([]byte, string) ([]attestation.Field, error)
	response func([]byte) ([]attestation.Field, error)
}

func (e textExtractorFuncs) ExtractRequest(body []byte, requestPath string) ([]attestation.Field, error) {
	return e.request(body, requestPath)
}

func (e textExtractorFuncs) ExtractResponse(body []byte) ([]attestation.Field, error) {
	return e.response(body)
}

var textExtractors = map[string]textExtractor{
	ExtractorOpenAIChatConversation: textExtractorFuncs{
		request:  extractOpenAIChatRequestConversation,
		response: extractOpenAIChatResponseConversation,
	},
	ExtractorOpenAIResponsesConversation: textExtractorFuncs{
		request:  extractOpenAIResponsesRequestConversation,
		response: extractOpenAIResponsesResponseConversation,
	},
	ExtractorAnthropicMessagesConversation: textExtractorFuncs{
		request:  extractMessagesRequestConversation,
		response: extractAnthropicResponseConversation,
	},
	ExtractorBedrockInvokeConversation: textExtractorFuncs{
		request:  extractMessagesRequestConversation,
		response: extractBedrockInvokeResponseConversation,
	},
	ExtractorBedrockConverseConversation: textExtractorFuncs{
		request:  extractMessagesRequestConversation,
		response: extractBedrockConverseResponseConversation,
	},
}

func lookupTextExtractor(name string) (textExtractor, bool) {
	extractor, ok := textExtractors[name]
	return extractor, ok
}

func IsSupportedExtractor(name string) bool {
	_, ok := lookupTextExtractor(name)
	return ok
}

type requestEnvelope struct {
	Model        string            `json:"model"`
	Messages     []json.RawMessage `json:"messages"`
	Input        json.RawMessage   `json:"input"`
	System       json.RawMessage   `json:"system"`
	Instructions json.RawMessage   `json:"instructions"`
}

type messageEnvelope struct {
	Type         string          `json:"type"`
	Role         string          `json:"role"`
	Content      json.RawMessage `json:"content"`
	Refusal      *string         `json:"refusal"`
	ToolCalls    json.RawMessage `json:"tool_calls"`
	FunctionCall json.RawMessage `json:"function_call"`
}

type contentBlock struct {
	Type    string  `json:"type"`
	Text    *string `json:"text"`
	Refusal *string `json:"refusal"`
}

func extractOpenAIChatRequestConversation(body []byte, requestPath string) ([]attestation.Field, error) {
	var request requestEnvelope
	if err := decodeJSONObject(body, &request); err != nil {
		return nil, err
	}
	messages, err := extractRequestMessages(request.Messages)
	if err != nil {
		return nil, err
	}
	model, err := requestModel(request.Model, requestPath)
	if err != nil {
		return nil, err
	}
	return conversationRequestFields(model, messages)
}

func extractMessagesRequestConversation(body []byte, requestPath string) ([]attestation.Field, error) {
	var request requestEnvelope
	if err := decodeJSONObject(body, &request); err != nil {
		return nil, err
	}
	messages, err := extractRequestMessages(request.Messages)
	if err != nil {
		return nil, err
	}
	if system, present, err := extractOptionalText(request.System, true); err != nil {
		return nil, fmt.Errorf("extract request system text: %w", err)
	} else if present {
		messages = append([]attestation.TextMessage{{Role: "system", Text: system}}, messages...)
	}
	model, err := requestModel(request.Model, requestPath)
	if err != nil {
		return nil, err
	}
	return conversationRequestFields(model, messages)
}

func extractOpenAIResponsesRequestConversation(body []byte, requestPath string) ([]attestation.Field, error) {
	var request requestEnvelope
	if err := decodeJSONObject(body, &request); err != nil {
		return nil, err
	}
	model, err := requestModel(request.Model, requestPath)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(request.Input)
	if len(trimmed) == 0 {
		return nil, errors.New("request input is required")
	}
	messages := make([]attestation.TextMessage, 0)
	if instructions, present, err := extractOptionalText(request.Instructions, true); err != nil {
		return nil, fmt.Errorf("extract request instructions text: %w", err)
	} else if present {
		messages = append(messages, attestation.TextMessage{Role: "system", Text: instructions})
	}
	if trimmed[0] == '"' {
		var input string
		if err := json.Unmarshal(trimmed, &input); err != nil {
			return nil, fmt.Errorf("decode string request input: %w", err)
		}
		messages = append(messages, attestation.TextMessage{Role: "user", Text: input})
		return conversationRequestFields(model, messages)
	}
	if trimmed[0] != '[' {
		return nil, errors.New("request input must be a string or an array of text messages")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, fmt.Errorf("decode request input array: %w", err)
	}
	if len(items) == 0 {
		return nil, errors.New("request input array must not be empty")
	}
	for index, rawItem := range items {
		var item messageEnvelope
		if err := decodeJSONObject(rawItem, &item); err != nil {
			return nil, fmt.Errorf("decode request input item %d: %w", index, err)
		}
		if item.Type != "" && item.Type != "message" {
			return nil, fmt.Errorf("request input item %d has unsupported non-text type %q", index, item.Type)
		}
		message, err := canonicalRequestMessage(item)
		if err != nil {
			return nil, fmt.Errorf("extract request input item %d: %w", index, err)
		}
		messages = append(messages, message)
	}
	return conversationRequestFields(model, messages)
}

func extractOpenAIChatResponseConversation(body []byte) ([]attestation.Field, error) {
	var response struct {
		Choices []struct {
			Message messageEnvelope `json:"message"`
		} `json:"choices"`
	}
	if err := decodeJSONObject(body, &response); err != nil {
		return nil, err
	}
	if len(response.Choices) != 1 {
		return nil, errors.New("response must contain exactly one choice")
	}
	message, err := canonicalResponseMessage(response.Choices[0].Message)
	if err != nil {
		return nil, fmt.Errorf("extract response message: %w", err)
	}
	return conversationResponseFields([]attestation.TextMessage{message})
}

func extractOpenAIResponsesResponseConversation(body []byte) ([]attestation.Field, error) {
	var response struct {
		Output []json.RawMessage `json:"output"`
	}
	if err := decodeJSONObject(body, &response); err != nil {
		return nil, err
	}
	messages := make([]attestation.TextMessage, 0)
	for index, rawItem := range response.Output {
		var item messageEnvelope
		if err := decodeJSONObject(rawItem, &item); err != nil {
			return nil, fmt.Errorf("decode response output item %d: %w", index, err)
		}
		if item.Type != "message" {
			continue
		}
		message, err := canonicalResponseMessage(item)
		if err != nil {
			return nil, fmt.Errorf("extract response output item %d: %w", index, err)
		}
		messages = append(messages, message)
	}
	if len(messages) == 0 {
		return nil, errors.New("response contains no text messages")
	}
	return conversationResponseFields(messages)
}

func extractAnthropicResponseConversation(body []byte) ([]attestation.Field, error) {
	var response struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := decodeJSONObject(body, &response); err != nil {
		return nil, err
	}
	message, err := canonicalResponseMessage(messageEnvelope{Role: response.Role, Content: response.Content})
	if err != nil {
		return nil, err
	}
	return conversationResponseFields([]attestation.TextMessage{message})
}

func extractBedrockInvokeResponseConversation(body []byte) ([]attestation.Field, error) {
	var response struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
		Output  *struct {
			Message messageEnvelope `json:"message"`
		} `json:"output"`
	}
	if err := decodeJSONObject(body, &response); err != nil {
		return nil, err
	}
	claudePresent := len(bytes.TrimSpace(response.Content)) > 0 && string(bytes.TrimSpace(response.Content)) != "null"
	novaPresent := response.Output != nil && len(bytes.TrimSpace(response.Output.Message.Content)) > 0
	if claudePresent == novaPresent {
		return nil, errors.New("Bedrock Invoke response must match exactly one supported text format")
	}
	message := messageEnvelope{Role: response.Role, Content: response.Content}
	if novaPresent {
		message = response.Output.Message
	}
	canonical, err := canonicalResponseMessage(message)
	if err != nil {
		return nil, err
	}
	return conversationResponseFields([]attestation.TextMessage{canonical})
}

func extractBedrockConverseResponseConversation(body []byte) ([]attestation.Field, error) {
	var response struct {
		Output *struct {
			Message messageEnvelope `json:"message"`
		} `json:"output"`
	}
	if err := decodeJSONObject(body, &response); err != nil {
		return nil, err
	}
	if response.Output == nil {
		return nil, errors.New("Bedrock Converse response output is required")
	}
	message, err := canonicalResponseMessage(response.Output.Message)
	if err != nil {
		return nil, err
	}
	return conversationResponseFields([]attestation.TextMessage{message})
}

func extractRequestMessages(rawMessages []json.RawMessage) ([]attestation.TextMessage, error) {
	if len(rawMessages) == 0 {
		return nil, errors.New("request messages must not be empty")
	}
	messages := make([]attestation.TextMessage, 0, len(rawMessages))
	for index, rawMessage := range rawMessages {
		var message messageEnvelope
		if err := decodeJSONObject(rawMessage, &message); err != nil {
			return nil, fmt.Errorf("decode request message %d: %w", index, err)
		}
		canonical, err := canonicalRequestMessage(message)
		if err != nil {
			return nil, fmt.Errorf("extract request message %d: %w", index, err)
		}
		messages = append(messages, canonical)
	}
	return messages, nil
}

func canonicalRequestMessage(message messageEnvelope) (attestation.TextMessage, error) {
	if !isRequestRole(message.Role) {
		return attestation.TextMessage{}, fmt.Errorf("unsupported request message role %q", message.Role)
	}
	if rawJSONPresent(message.ToolCalls) || rawJSONPresent(message.FunctionCall) {
		return attestation.TextMessage{}, errors.New("request message contains an unsupported tool call")
	}
	text, found, err := extractContentText(message.Content, true)
	if err != nil {
		return attestation.TextMessage{}, err
	}
	if !found {
		return attestation.TextMessage{}, errors.New("request message contains no text")
	}
	return attestation.TextMessage{Role: message.Role, Text: text}, nil
}

func canonicalResponseMessage(message messageEnvelope) (attestation.TextMessage, error) {
	if message.Role != "assistant" {
		return attestation.TextMessage{}, fmt.Errorf("unsupported response message role %q", message.Role)
	}
	text, found, err := extractContentText(message.Content, false)
	if err != nil {
		return attestation.TextMessage{}, err
	}
	if message.Refusal != nil {
		if found {
			return attestation.TextMessage{}, errors.New("response message contains both content text and refusal text")
		}
		text, found = *message.Refusal, true
	}
	if !found {
		return attestation.TextMessage{}, errors.New("response message contains no final text")
	}
	return attestation.TextMessage{Role: "assistant", Text: text}, nil
}

func isRequestRole(role string) bool {
	switch role {
	case "system", "developer", "user", "assistant":
		return true
	default:
		return false
	}
}

func extractOptionalText(raw json.RawMessage, rejectNonText bool) (string, bool, error) {
	return extractContentText(raw, rejectNonText)
}

func rawJSONPresent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) && !bytes.Equal(trimmed, []byte("[]"))
}

func extractContentText(raw json.RawMessage, rejectNonText bool) (string, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", false, nil
	}
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return "", false, err
		}
		return text, true, nil
	}
	if trimmed[0] != '[' {
		return "", false, errors.New("message content must be a string or an array")
	}
	var blocks []json.RawMessage
	if err := json.Unmarshal(trimmed, &blocks); err != nil {
		return "", false, err
	}
	var result strings.Builder
	foundText := false
	for index, rawBlock := range blocks {
		var block contentBlock
		if err := decodeJSONObject(rawBlock, &block); err != nil {
			return "", false, fmt.Errorf("decode content block %d: %w", index, err)
		}
		isText := block.Type == "text" || block.Type == "input_text" || block.Type == "output_text" || block.Type == "refusal" || (block.Type == "" && block.Text != nil)
		if !isText {
			if rejectNonText {
				return "", false, fmt.Errorf("content block %d has unsupported non-text type %q", index, block.Type)
			}
			continue
		}
		value := block.Text
		if block.Type == "refusal" && value == nil {
			value = block.Refusal
		}
		if value == nil {
			return "", false, fmt.Errorf("text content block %d has no text value", index)
		}
		foundText = true
		result.WriteString(*value)
	}
	return result.String(), foundText, nil
}

func requestModel(bodyModel, requestPath string) (string, error) {
	if bodyModel != "" {
		return bodyModel, nil
	}
	segments := strings.Split(strings.Trim(requestPath, "/"), "/")
	for index, segment := range segments {
		if (segment == "deployments" || segment == "model") && index+1 < len(segments) {
			model, err := url.PathUnescape(segments[index+1])
			if err != nil {
				return "", fmt.Errorf("decode model from request path: %w", err)
			}
			if model != "" {
				return model, nil
			}
		}
	}
	return "", errors.New("request model is required in the body or request path")
}

func conversationRequestFields(model string, messages []attestation.TextMessage) ([]attestation.Field, error) {
	modelField, err := newStringField("model", model)
	if err != nil {
		return nil, err
	}
	messagesField, err := newJSONField("messages", messages)
	if err != nil {
		return nil, err
	}
	return []attestation.Field{modelField, messagesField}, nil
}

func conversationResponseFields(messages []attestation.TextMessage) ([]attestation.Field, error) {
	field, err := newJSONField("messages", messages)
	if err != nil {
		return nil, err
	}
	return []attestation.Field{field}, nil
}

func newJSONField(name string, value any) (attestation.Field, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return attestation.Field{}, err
	}
	return attestation.NewField(name, raw)
}

func newStringField(name, value string) (attestation.Field, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return attestation.Field{}, err
	}
	return attestation.NewField(name, raw)
}

func decodeJSONObject(data []byte, target any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("value must be a JSON object")
	}
	if err := validateUniqueJSON(trimmed); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected data after JSON object")
		}
		return fmt.Errorf("decode trailing JSON data: %w", err)
	}
	return nil
}

func validateUniqueJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("JSON must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected data after JSON value")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key must be a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("JSON object contains duplicate key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object is not properly closed")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array is not properly closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
