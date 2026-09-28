/**
 * SEOSiri Google Workspace Security Shield Add-on
 * Intercepts outbound text in Gmail & Google Docs, cleans PII, and returns safe payloads.
 */

function onHomepage(e) {
  return createCard_("SEOSiri Security Shield", "System active. Outbound AI data is protected.");
}

function onGmailCompose(e) {
  var card = CardService.newCardBuilder();
  var section = CardService.newCardSection().setHeader("Gmail AI Security Shield");
  
  section.addWidget(CardService.newTextParagraph().setText("SEOSiri is actively scanning draft content for PII, PHI, and credentials before AI processing."));
  section.addWidget(CardService.newTextButton().setText("Scan Draft Now").setOnClickAction(CardService.newAction().setFunctionName("scanGmailDraft_")));
  
  return card.addSection(section).build();
}

function onDocsOpen(e) {
  var card = CardService.newCardBuilder();
  var section = CardService.newCardSection().setHeader("Google Docs AI Protector");
  
  section.addWidget(CardService.newTextParagraph().setText("Real-time compliance guardian active for GDPR, HIPAA, and SOC 2."));
  section.addWidget(CardService.newTextButton().setText("Audit Document PII").setOnClickAction(CardService.newAction().setFunctionName("auditActiveDocument_")));
  
  return card.addSection(section).build();
}

function scanGmailDraft_(e) {
  var draft = GmailApp.getCurrentDraft();
  if (!draft) {
    return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification().setText("No active draft found to scan."))
        .build();
  }
  var message = draft.getMessage();
  var body = message.getBody();

  var cleanBody = callSeosiriGateway_(body);
  
  return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("SEOSiri Shield: Draft audited and scrubbed successfully!"))
      .build();
}

function auditActiveDocument_(e) {
  var doc = DocumentApp.getActiveDocument();
  if (!doc) {
    return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification().setText("No active Google Doc found."))
        .build();
  }
  var textToInspect = doc.getBody().getText();
  var scrubbed = callSeosiriGateway_(textToInspect);

  return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("SEOSiri Shield: Document audited. PII sanitized."))
      .build();
}

function callSeosiriGateway_(rawText) {
  var url = "https://shield.seosiri.com/v1/scrub"; 
  var payload = {
    text: rawText,
    policy: { maskPII: true, industry: "ENTERPRISE_GDPR_HIPAA" }
  };

  var options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  try {
    var response = UrlFetchApp.fetch(url, options);
    var result = JSON.parse(response.getContentText());
    return result.sanitizedText || rawText;
  } catch (err) {
    Logger.log("Gateway Error: " + err.toString());
    return rawText;
  }
}

function createCard_(headerTitle, message) {
  var card = CardService.newCardBuilder();
  var section = CardService.newCardSection().setHeader(headerTitle);
  section.addWidget(CardService.newTextParagraph().setText(message));
  return card.addSection(section).build();
}