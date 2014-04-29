#!/bin/bash

###
# Copyright 2013 AppDynamics
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###

LOG_FILE=/var/log/victorops-appdynamics.log
exec >> $LOG_FILE 2>&1

PROTOCOL=https
VO_ALERT_HOST=alert.victorops.com

## Import external parameters
. params.sh

## POLICY VIOLATION VARIABLES
APP_NAME="${1//\"/}"
APP_ID="${2//\"/}"
PVN_ALERT_TIME="${3//\"/}"
PRIORITY="${4//\"/}"
SEVERITY="${5//\"/}"
TAG="${6//\"/}"
HEALTH_RULE_NAME="${7//\"/}"
HEALTH_RULE_ID="${8//\"/}"
PVN_TIME_PERIOD_IN_MINUTES="${9//\"/}"
AFFECTED_ENTITY_TYPE="${10//\"/}"
AFFECTED_ENTITY_NAME="${11//\"/}"
AFFECTED_ENTITY_ID="${12//\"/}"
NUMBER_OF_EVALUATION_ENTITIES="${13//\"/}"

## SUMMARY VARIABLES
SUMMARY="{ \"Application Name\": \"$APP_NAME\",
\"Policy Violation Alert Time\": \"$PVN_ALERT_TIME\",
\"Severity\": \"$SEVERITY\",
\"Priority\": \"$PRIORITY\",
\"Name of Violated Health Rule\": \"$HEALTH_RULE_NAME\",
\"Affected Entity Type\": \"$AFFECTED_ENTITY_TYPE\",
\"Name of Affected Entity\": \"$AFFECTED_ENTITY_NAME\","

## SET CURRENT PARAMETER LOCATION
CURP=13

## LOOP THROUGH AND GET VARIABLES OF ALL EVALUATION ENTITIES
for i in `seq 1 $NUMBER_OF_EVALUATION_ENTITIES`
do
    SUMMARY=$SUMMARY"""\"EVALUATION ENTITY #"""$i"""\":\"\","

    ((CURP = 1 + $CURP))
    EVALUATION_ENTITY_TYPE="${!CURP}"
    EVALUATION_ENTITY_TYPE="${EVALUATION_ENTITY_TYPE//\"/}"

    SUMMARY=$SUMMARY"""\"Evaluation Entity Type\": \""""$EVALUATION_ENTITY_TYPE"""\","

    ((CURP = 1 + $CURP))
    EVALUATION_ENTITY_NAME="${!CURP}"
    EVALUATION_ENTITY_NAME="${EVALUATION_ENTITY_NAME//\"/}"

    SUMMARY=$SUMMARY"""\"Evaluation Entity Name\": \""""$EVALUATION_ENTITY_NAME"""\","

    ((CURP = 1 + $CURP))
    EVALUATION_ENTITY_ID="${!CURP}"
    EVALUATION_ENTITY_ID="${EVALUATION_ENTITY_ID//\"/}"

    SUMMARY=$SUMMARY"""\"Evaluation Entity ID\": \""""$EVALUATION_ENTITY_ID"""\","

    ((CURP = 1 + $CURP))
    NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY="${!CURP}"
    NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY="${NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY//\"/}"

    SUMMARY=$SUMMARY"""\"Number of Triggered Conditions for """$EVALUATION_ENTITY_NAME"""\": \""""$NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY"""\","

    ## GET VARIABLES OF TRIGGERED CONDITIONS
    for trig in `seq 1 $NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY`
    do

        SUMMARY=$SUMMARY"""\"Triggered Condition #"""$trig"""\":\"\","

        ((CURP = 1 + $CURP))
    SCOPE_TYPE_x="${!CURP}"
    SCOPE_TYPE_x="${SCOPE_TYPE_x//\"/}"

        SUMMARY=$SUMMARY"""\"Scope Type\": \""""$SCOPE_TYPE_x"""\","

        ((CURP = 1 + $CURP))
    SCOPE_NAME_x="${!CURP}"
    SCOPE_NAME_x="${SCOPE_NAME_x//\"/}"

    SUMMARY=$SUMMARY"""\"Scope Name\": \""""$SCOPE_NAME_x"""\","

        ((CURP = 1 + $CURP))
    SCOPE_ID_x="${!CURP}"
    SCOPE_ID_x="${SCOPE_ID_x//\"/}"

        SUMMARY=$SUMMARY"""\"Scope ID\": \""""$SCOPE_ID_x"""\","

        ((CURP = 1 + $CURP))
    CONDITION_NAME_x="${!CURP}"
    CONDITION_NAME_x="${CONDITION_NAME_x//\"/}"

        SUMMARY=$SUMMARY"""\"Condition Name\": \""""$CONDITION_NAME_x"""\","

        ((CURP = 1 + $CURP))
    CONDITION_ID_x="${!CURP}"
    CONDITION_ID_x="${CONDITION_ID_x//\"/}"

        SUMMARY=$SUMMARY"""\"Condition ID\": \""""$CONDITION_ID_x"""\","

        ((CURP = 1 + $CURP))
    OPERATOR_x="${!CURP}"
    OPERATOR_x="${OPERATOR_x//\"/}"

    if [ "$OPERATOR_x" = "LESS_THAN" ]; then
        OPERATOR_x="<"
    elif [ "$OPERATOR_x" = "LESS_THAN_EQUALS" ]; then
        OPERATOR_x="<="
    elif [ "$OPERATOR_x" = "GREATER_THAN" ]; then
        OPERATOR_x=">"
    elif [ "$OPERATOR_x" = "GREATER_THAN_EQUALS" ]; then
        OPERATOR_x=">="
    elif [ "$OPERATOR_x" = "EQUALS" ]; then
        OPERATOR_x="=="
    elif [ "$OPERATOR" = "NOT_EQUALS" ]; then
        OPERATOR_x="!="
        fi

        SUMMARY=$SUMMARY"""\"Operator\": \""""$OPERATOR_x"""\","

        ((CURP = 1 + $CURP))
    CONDITION_UNIT_TYPE_x="${!CURP}"
    CONDITION_UNIT_TYPE_x="${CONDITION_UNIT_TYPE_x//\"/}"

        SUMMARY=$SUMMARY"""\"Condition Unit Type\": \""""$CONDITION_UNIT_TYPE_x"""\","

        ISBASELINE=${CONDITION_UNIT_TYPE_x:0:9}

        SUMMARY=$SUMMARY"""\"Condition Unit Type SubString\": \""""$ISBASELINE"""\","

    if [ "$ISBASELINE" == "BASELINE_" ]
      then
            ((CURP = 1 + $CURP))
        USE_DEFAULT_BASELINE_x="${!CURP}"
        USE_DEFAULT_BASELINE_x="${USE_DEFAULT_BASELINE_x//\"/}"

        SUMMARY=$SUMMARY"""\"Is Default Baseline?\" : \""""$USE_DEFAULT_BASELINE_x"""\","

            if [ "$USE_DEFAULT_BASELINE_x" == "false" ]
              then
                ((CURP = 1 + $CURP))
            BASELINE_NAME_x="${!CURP}"
            BASELINE_NAME_x="${BASELINE_NAME_x//\"/}"

            SUMMARY=$SUMMARY"""\"Baseline Name\": \""""$BASELINE_NAME_x"""\","

                ((CURP = 1 + $CURP))
            BASELINE_ID_x="${!CURP}"
            BASELINE_ID_x="${BASELINE_ID_x//\"/}"

                SUMMARY=$SUMMARY"""\"Baseline ID\": \""""$BASELINE_ID_x"""\","
            fi
    fi

        ((CURP = 1 + $CURP))
    THRESHOLD_VALUE_x="${!CURP}"
    THRESHOLD_VALUE_x="${THRESHOLD_VALUE_x//\"/}"

        SUMMARY=$SUMMARY"""\"Threshold Value\": \""""$THRESHOLD_VALUE_x"""\","
    ##SUMMARY=$SUMMARY"""\""""$CONDITION_NAME_x""" """$OPERATOR_x""" """$THRESHOLD_VALUE_x"""\":\"\","

        ((CURP = 1 + $CURP))
    OBSERVED_VALUE_x="${!CURP}"
    OBSERVED_VALUE_x="${OBSERVED_VALUE_x//\"/}"

    SUMMARY=$SUMMARY"""\"Observed Value\" : \""""$OBSERVED_VALUE_x"""\","

    done
done

((CURP = 1 + $CURP))
SUMMARY_MESSAGE="${!CURP}"
SUMMARY_MESSAGE="${SUMMARY_MESSAGE//\"/}"

((CURP = 1 + $CURP))
INCIDENT_ID="${!CURP}"
INCIDENT_ID="${INCIDENT_ID//\"/}"

((CURP = 1 + $CURP))
DEEP_LINK_URL="${!CURP}"
DEEP_LINK_URL="${DEEP_LINK_URL//\"/}"

((CURP = 1 + $CURP))
if [ "$CURP" -le $# ]
    then # Version 3.7 or higher
    EVENT_TYPE="${!CURP}"
    EVENT_TYPE="${EVENT_TYPE//\"/}"
else
    EVENT_TYPE = "POLICY_OPEN" # Version 3.6 or lower
fi

SUMMARY=$SUMMARY"""\"Incident ID\": \""""$INCIDENT_ID"""\""
SUMMARY=$SUMMARY"""}"

echo ------ Action Initiated ------
echo "Send alert to VictorOps at " $PVN_ALERT_TIME

if [ "$EVENT_TYPE" = "POLICY_CLOSE" ]; then
    MSG_TYPE="RECOVERY"
elif [ "$SEVERITY" = "WARN" ]; then
    MSG_TYPE="WARNING"
elif [ "$SEVERITY" = "ERROR" ]; then
    MSG_TYPE="CRITICAL"
else
    MSG_TYPE="INFO"
fi

ENTITY_ID="$APP_ID-$AFFECTED_ENTITY_ID-$HEALTH_RULE_ID"
DISP_NAME="$APP_NAME/$AFFECTED_ENTITY_NAME/$HEALTH_RULE_NAME"

echo ====== PARAMETERS ======
echo "EVENT_TYPE: $EVENT_TYPE"
echo "message_type: $MSG_TYPE"
echo "entity_id: $ENTITY_ID"
echo "VO_ORGANIZATION_KEY: $VO_ORGANIZATION_KEY"
echo "VO_ROUTING_KEY: $VO_ROUTING_KEY"
echo "state_message: $SUMMARY_MESSAGE"
echo "entity_display_name: $DISP_NAME"
echo "description: $HEALTH_RULE_NAME"
echo "details: $SUMMARY"

echo ====== RESPONSE ======
curl -H "Content-type: application/json" -X POST -d '{
  "message_type": "'"$MSG_TYPE"'",
  "entity_id": "'"$ENTITY_ID"'",
  "VO_ORGANIZATION_KEY": "'"$VO_ORGANIZATION_KEY"'",
  "VO_ROUTING_KEY": "'"$VO_ROUTING_KEY"'",
  "state_message": "'"$SUMMARY_MESSAGE"'",
  "entity_display_name": "'"$DISP_NAME"'",
  "ad_event_type": "'"$EVENT_TYPE"'",
  "alert_url": "'"$DEEP_LINK_URL$INCIDENT_ID"'",
  "ap_details": '"$SUMMARY"',
  "monitoring_tool": "AppDynamics"
}' "$PROTOCOL://$VO_ALERT_HOST/integrations/generic/20131114/alert"

echo ------ Action Completed ------
