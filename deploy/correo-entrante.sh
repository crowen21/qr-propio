#!/usr/bin/env bash
# Recibe los correos dirigidos a contacto@facilqr.cl y los reenvía a un correo personal.
# Se ejecuta UNA vez en AWS CloudShell (región us-east-1):
#   bash correo-entrante.sh facilqr.cl contacto destino@gmail.com
# Flujo: MX del dominio -> Amazon SES (recepción) -> S3 (copia 30 días) -> Lambda -> reenvío por SES.
set -euo pipefail
DOMINIO="$1"; BUZON="$2"; DESTINO="$3"
REGION=us-east-1
CUENTA=$(aws sts get-caller-identity --query Account --output text)
BUCKET="${DOMINIO//./-}-correo-entrante-$CUENTA"
ROL=facilqr-reenvio-correo
FUNCION=facilqr-reenvio-correo
REGLAS=facilqr-entrante
ZONA=$(aws route53 list-hosted-zones-by-name --dns-name "$DOMINIO" --query 'HostedZones[0].Id' --output text | cut -d/ -f3)

echo "1/6 Bucket para la copia de los correos (se borran a los 30 días)"
aws s3api create-bucket --bucket "$BUCKET" --region $REGION >/dev/null 2>&1 || true
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" --lifecycle-configuration \
  '{"Rules":[{"ID":"borrar-30-dias","Status":"Enabled","Filter":{"Prefix":""},"Expiration":{"Days":30}}]}'
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ses.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceAccount\":\"$CUENTA\"}}}]}"

echo "2/6 Permisos de la función de reenvío"
aws iam create-role --role-name $ROL --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null 2>&1 || true
aws iam put-role-policy --role-name $ROL --policy-name reenviar --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[
 {\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/*\"},
 {\"Effect\":\"Allow\",\"Action\":[\"ses:SendRawEmail\",\"ses:SendEmail\"],\"Resource\":\"*\",\"Condition\":{\"StringLike\":{\"ses:FromAddress\":\"*@$DOMINIO\"}}},
 {\"Effect\":\"Allow\",\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\"],\"Resource\":\"*\"}]}"

echo "3/6 Función de reenvío"
TMP=$(mktemp -d)
cat > "$TMP/lambda_function.py" <<'PY'
import email, email.policy, os, boto3
from email.utils import parseaddr, formataddr
s3, ses = boto3.client("s3"), boto3.client("ses")

def lambda_handler(event, context):
    rec = event["Records"][0]["ses"]
    if rec["receipt"]["spamVerdict"]["status"] == "FAIL" or rec["receipt"]["virusVerdict"]["status"] == "FAIL":
        return {"disposition": "STOP_RULE_SET"}  # no se reenvía spam ni virus
    obj = s3.get_object(Bucket=os.environ["BUCKET"], Key=rec["mail"]["messageId"])
    msg = email.message_from_bytes(obj["Body"].read(), policy=email.policy.default)
    nombre, correo = parseaddr(str(msg.get("From", "")))
    for h in ("From", "Reply-To", "Sender", "Return-Path", "DKIM-Signature", "Message-ID", "To", "Cc", "Bcc"):
        del msg[h]
    msg["From"] = formataddr((f"{nombre or correo} vía FacilQR", os.environ["REMITENTE"]))
    msg["Reply-To"] = correo
    msg["To"] = os.environ["DESTINO"]
    ses.send_raw_email(Source=os.environ["REMITENTE"], Destinations=[os.environ["DESTINO"]],
                       RawMessage={"Data": msg.as_bytes()})
    return {"disposition": "CONTINUE"}
PY
(cd "$TMP" && zip -q funcion.zip lambda_function.py)
ROL_ARN=$(aws iam get-role --role-name $ROL --query Role.Arn --output text)
sleep 10  # el rol recién creado tarda unos segundos en estar disponible
VARS="Variables={BUCKET=$BUCKET,DESTINO=$DESTINO,REMITENTE=reenvio@$DOMINIO}"
if aws lambda get-function --function-name $FUNCION >/dev/null 2>&1; then
  aws lambda update-function-code --function-name $FUNCION --zip-file "fileb://$TMP/funcion.zip" >/dev/null
  aws lambda wait function-updated --function-name $FUNCION
  aws lambda update-function-configuration --function-name $FUNCION --environment "$VARS" >/dev/null
else
  aws lambda create-function --function-name $FUNCION --runtime python3.12 --handler lambda_function.lambda_handler \
    --role "$ROL_ARN" --timeout 30 --zip-file "fileb://$TMP/funcion.zip" --environment "$VARS" >/dev/null
fi
aws lambda add-permission --function-name $FUNCION --statement-id ses-invoca --action lambda:InvokeFunction \
  --principal ses.amazonaws.com --source-account "$CUENTA" >/dev/null 2>&1 || true
FUNCION_ARN=$(aws lambda get-function --function-name $FUNCION --query Configuration.FunctionArn --output text)

echo "4/6 Regla de recepción en SES para $BUZON@$DOMINIO"
aws ses create-receipt-rule-set --rule-set-name $REGLAS >/dev/null 2>&1 || true
aws ses delete-receipt-rule --rule-set-name $REGLAS --rule-name contacto >/dev/null 2>&1 || true
aws ses create-receipt-rule --rule-set-name $REGLAS --rule "{\"Name\":\"contacto\",\"Enabled\":true,\"ScanEnabled\":true,\"TlsPolicy\":\"Optional\",
  \"Recipients\":[\"$BUZON@$DOMINIO\"],
  \"Actions\":[{\"S3Action\":{\"BucketName\":\"$BUCKET\"}},{\"LambdaAction\":{\"FunctionArn\":\"$FUNCION_ARN\",\"InvocationType\":\"Event\"}}]}"
aws ses set-active-receipt-rule-set --rule-set-name $REGLAS

echo "5/6 Registros DNS: MX para recibir y DMARC"
aws route53 change-resource-record-sets --hosted-zone-id "$ZONA" --change-batch "{\"Changes\":[
 {\"Action\":\"UPSERT\",\"ResourceRecordSet\":{\"Name\":\"$DOMINIO\",\"Type\":\"MX\",\"TTL\":300,\"ResourceRecords\":[{\"Value\":\"10 inbound-smtp.$REGION.amazonaws.com\"}]}},
 {\"Action\":\"UPSERT\",\"ResourceRecordSet\":{\"Name\":\"_dmarc.$DOMINIO\",\"Type\":\"TXT\",\"TTL\":300,\"ResourceRecords\":[{\"Value\":\"\\\"v=DMARC1; p=none\\\"\"}]}}]}" >/dev/null

echo "6/6 Listo: los correos a $BUZON@$DOMINIO se reenvían a $DESTINO (puede tardar unos minutos en propagarse)."
