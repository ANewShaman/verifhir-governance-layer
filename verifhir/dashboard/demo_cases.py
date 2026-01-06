"""
Demo Cases - Medical Records Data Structure
Extracted from demo_case_raw.docx
Contains sample medical records across different privacy regulations (HIPAA, LGPD, GDPR, DPDP)
"""

demo_cases = {
    "hipaa": {
        "structured_discharge_summary": {
            "patient_name": "Jonathan Michael Reeves",
            "dob": "07/22/1981",
            "mrn": "MRN-5527819",
            "ssn": "317-44-9821",
            "address": "4182 North Elm Street, Apt 5C, Madison, WI 53704",
            "phone": "(608) 555-4179",
            "admission_date": "03/11/2025",
            "discharge_date": "03/14/2025",
            "admitting_diagnosis": "Community-acquired pneumonia",
            "discharge_diagnosis": "Community-acquired pneumonia, resolved",
            "past_medical_history": ["Hypertension", "Seasonal allergic rhinitis"],
            "medications_on_discharge": [
                "Amoxicillin-clavulanate 875 mg twice daily for 5 days",
                "Lisinopril 10 mg daily"
            ],
            "attending_physician": "Laura K. Benson, MD",
            "facility": "Lakeside Regional Medical Center"
        },
        "json_fhir": {
            "resourceType": "Patient",
            "id": "hipaa-json-001",
            "identifier": [
                {"system": "urn:mrn:lakeside", "value": "MRN-8842031"},
                {"system": "urn:ssn:us", "value": "529-61-3047"}
            ],
            "name": [{"family": "Carter", "given": ["Melissa", "Anne"]}],
            "gender": "female",
            "birthDate": "1976-10-05",
            "address": [{
                "line": ["902 Willow Creek Drive"],
                "city": "Plano",
                "state": "TX",
                "postalCode": "75023",
                "country": "USA"
            }],
            "telecom": [{"system": "phone", "value": "(469) 555-9082"}]
        },
        "unstructured_text": """Melissa Carter, DOB 10/05/1976, residing at 902 Willow Creek Drive, Plano, Texas, was admitted on 01/19/2025 for evaluation of acute abdominal pain. The patient's medical record number is MRN-8842031 and her Social Security number was verified during registration.

She reported worsening right upper quadrant pain for two days associated with nausea. Past medical history includes hyperlipidemia. The patient lives with her spouse and is employed full-time as an office manager.

Imaging studies were consistent with acute cholecystitis. The patient underwent laparoscopic cholecystectomy on 01/20/2025 without complication. She was discharged on 01/22/2025 in stable condition with instructions to follow up with general surgery in one week.

Emergency contact listed as spouse, Daniel Carter, phone (469) 555-7741.""",
        "hl7_v2_adt": """MSH|^~\\&|EHRSystem|LakesideMC|ADTService|LakesideMC|202503141030||ADT^A03|H123456|P|2.5
PID|1||5527819^^^MRN||REEVES^JONATHAN^M||19810722|M|||4182 N ELM ST^APT 5C^MADISON^WI^53704||6085554179|||M||317-44-9821
PV1|1|I|MEDSURG^301^1||||||12345^BENSON^LAURA^K||||||||||||V|||||202503111200|202503141015""",
        "ocr_style": """LAKESIDE REGIONAL MEDICAL CENTER
Scanned Document - Admission Form

Patient: Jonathan Michael Reeves
DOB: 07/22/1981
MRN: 5527819
SSN: 317-44-9821
Address: 4182 North Elm Street, Apt 5C, Madison, WI 53704
Phone: (608) 555-4179

Admission: 03/11/2025
Reason: Community-acquired pneumonia

Employment: Software Engineer
Marital Status: Married

Signature: [illegible]
Notes: Patient presented with fever and cough. Lives with spouse."""
    },
    
    "lgpd": {
        "json_fhir": {
            "resourceType": "Patient",
            "id": "lgpd-br-001",
            "name": [{"family": "Albuquerque", "given": ["Renata"]}],
            "gender": "female",
            "birthDate": "1989-08-27",
            "address": [{
                "line": ["Rua das Palmeiras, 245", "Apto 31"],
                "city": "Campinas",
                "state": "SP",
                "postalCode": "13015-210",
                "country": "Brasil"
            }],
            "identifier": [{"system": "urn:gov.br:cpf", "value": "389.742.615-90"}],
            "telecom": [{"system": "phone", "value": "+55 19 9XXXX-7712", "use": "mobile"}],
            "extension": [
                {"url": "employment-context", "valueString": "Analista administrativa em empresa privada do setor de transportes"},
                {"url": "household-context", "valueString": "Reside com o cônjuge e um filho em idade escolar"}
            ]
        },
        "unstructured_text": """A paciente Renata Albuquerque, residente à Rua das Palmeiras, 245, Apto 31, Campinas -- SP, procurou atendimento em 18/04/2024 com queixa de cefaleia persistente e episódios de tontura. Informou CPF 389.742.615-90 durante o cadastro administrativo.

Relata rotina de trabalho prolongada como analista administrativa em empresa do setor de transportes, com frequentes horas extras e uso contínuo de computador. Vive com o marido e o filho de 8 anos, sendo a principal responsável pela organização doméstica.

Antecedentes pessoais incluem enxaqueca desde a adolescência. Histórico familiar positivo para hipertensão arterial em ambos os pais. Ao exame físico, não foram observadas alterações neurológicas.

Orientada quanto à adequação da rotina de trabalho, hidratação e acompanhamento ambulatorial. Retorno sugerido em caso de persistência ou piora dos sintomas.""",
        "structured_text": {
            "nome": "Carlos Eduardo Nogueira",
            "cpf": "517.093.284-61",
            "endereco": "Avenida Beira-Mar Norte, 1180, Florianópolis -- SC, CEP 88015-100",
            "data_atendimento": "07/09/2024",
            "motivo_consulta": "dor lombar crônica",
            "historico": "Paciente refere dor lombar há aproximadamente seis meses, associada a esforço físico frequente. Trabalha como motorista de aplicativo e permanece longos períodos sentado.",
            "contexto_pessoal": "Reside sozinho em apartamento alugado. Possui renda variável mensal.",
            "conduta": "Prescrito analgésico simples e orientações posturais. Encaminhamento para fisioterapia ambulatorial."
        },
        "hl7_v2_adt": """MSH|^~\\&|HospitalSys|BR_HOSP|CareApp|STATE_HEALTH|202404181030||ADT^A01|LGPD123456|P|2.5
PID|1||LGPD001^^^LOCAL||ALBUQUERQUE^RENATA||19890827|F|||RUA DAS PALMEIRAS^245^APT 31^CAMPINAS^SP^13015210||+55199XXXX7712|||S||CPF^38974261590
PV1|1|I|NEURO^101^1|||DRMED^JOSE|||||||||||VN20240418""",
        "ocr_style": """CLÍNICA VIDA SAÚDE INTEGRADA
Documento digitalizado -- qualidade variável

Nome do paciente: Juliana Costa Ribeiro
CPF: 604.281.739-02
Endereço: Rua Joaquim Silva, 92, Bairro Centro, Recife -- PE
Data de atendimento: 22/05/2024

Convênio informado no atendimento
Profissão declarada: atendente de call center
Estado civil: solteira

Motivo do atendimento: avaliação clínica após afastamento do trabalho por dor no punho direito

Observações:
Paciente relata uso intenso de computador e telefone durante jornada diária. Compareceu desacompanhada. Informou residir próxima ao local de trabalho e depender de transporte público."""
    },
    
    "uk_gdpr": {
        "json_fhir": {
            "resourceType": "Patient",
            "id": "ukgdpr-001",
            "identifier": [{"system": "https://fhir.nhs.uk/Id/nhs-number", "value": "987 654 3210"}],
            "name": [{"family": "Thompson", "given": ["Emily"]}],
            "gender": "female",
            "birthDate": "1989-02-17",
            "address": [{
                "line": ["Flat 5B, Rosewood Court", "Holloway Road"],
                "city": "London",
                "postalCode": "N7 8LT",
                "country": "United Kingdom"
            }],
            "extension": [
                {"url": "household-context", "valueString": "Lives with partner and two school-aged children"},
                {"url": "employment-context", "valueString": "Employed part-time as a library assistant at a local borough council"}
            ]
        },
        "unstructured_discharge_note": """Emily Thompson was admitted on 06/05/2024 for assessment following recurrent episodes of dizziness and fatigue. She resides at Flat 5B, Rosewood Court, Holloway Road, London N7 8LT, and is registered with a local GP practice within the Camden borough. Her NHS number was confirmed at admission.

The patient reported increased stress related to balancing part-time employment with childcare responsibilities. She lives with her partner and two children, both attending a nearby secondary school. Past medical history includes iron-deficiency anaemia diagnosed in 2021.

Routine blood tests were performed and showed mildly reduced haemoglobin levels. No acute pathology was identified. Oral iron supplementation was recommenced, and dietary advice was provided.

The patient was discharged on 07/05/2024 with advice to follow up with her GP within four weeks.""",
        "structured_referral": {
            "facility": "Northway Community Health Centre",
            "date": "14/09/2024",
            "patient_name": "Daniel Wright",
            "nhs_number": "564 998 2301",
            "address": "21 Brookfield Terrace, Leeds LS6 2AB",
            "referral_reason": "Further neurological assessment following intermittent episodes of unilateral numbness and headaches",
            "employment": "delivery coordinator",
            "referring_physician": "Dr Hannah Collins"
        },
        "hl7_v2_adt": """MSH|^~\\&|GPSystem|UK_NHS|ADTService|UK_NHS|202405071030||ADT^A03|UK123456|P|2.5
PID|1||9876543210^^^NHS||THOMPSON^EMILY||19890217|F|||FLAT 5B ROSEWOOD COURT^HOLLOWAY ROAD^LONDON^^N78LT||+44XXXXXXXXXX|||M||NHS^9876543210
PV1|1|I|MED^101^1||||DRCOLLINS^HANNAN|||||||||||V|||||202405061200|202405071015""",
        "ocr_style": """NORTHWAY COMMUNITY HEALTH CENTRE
Scanned Referral Document

Patient: Daniel Wright
NHS No: 564 998 2301
Address: 21 Brookfield Terrace, Leeds LS6 2AB
Date: 14/09/2024

Referral to: Neurology Outpatient
Reason: Intermittent numbness and headaches

Employment: Delivery Coordinator
Marital Status: Married

Notes: Patient reports symptoms after long hours. Lives with spouse.
Signature: [illegible]"""
    },
    
    "eu_gdpr": {
        "german_json": {
            "documentType": "ClinicalDischargeNote",
            "patient": {
                "name": "Lukas Schneider",
                "address": {
                    "street": "Bergstraße 22",
                    "city": "Heidelberg",
                    "postalCode": "69120",
                    "country": "Germany"
                },
                "dateOfBirth": "1987-04-11"
            },
            "admission": {"date": "03/10/2024", "reason": "Abklärung wiederkehrender Schwindelanfälle"},
            "clinicalContext": {
                "history": ["Migräne seit dem Studium", "Arbeitsbedingter Stress"],
                "employment": "Projektleiter in einem mittelständischen IT-Unternehmen"
            },
            "discharge": {"date": "05/10/2024"}
        },
        "french_unstructured": """La patiente, Claire Moreau, a été admise le 07/09/2024 pour une prise en charge de douleurs thoraciques intermittentes apparues depuis une semaine. Elle réside au 14 rue des Tilleuls, 2ᵉ étage, à Tours, et vit avec son conjoint et leur enfant âgé de six ans. Elle travaille actuellement comme responsable administrative dans une entreprise de logistique située en périphérie de la ville.

Les antécédents médicaux incluent une hypertension artérielle diagnostiquée en 2021, traitée de façon irrégulière. La sortie a été autorisée le 09/09/2024 avec recommandation de suivi auprès du médecin traitant.""",
        "spanish_semi_structured": {
            "paciente": "Marta López",
            "fecha_ingreso": "18/11/2024",
            "fecha_alta": "21/11/2024",
            "residencia": "calle Alcalá, Madrid",
            "ocupacion": "diseñadora gráfica de forma autónoma",
            "diagnostico": "episodios recurrentes de dificultad respiratoria leve"
        },
        "hl7_v2_adt": """MSH|^~\\&|HospitalSys|EU_HOSP|CareApp|EU_HEALTH|202409091030||ADT^A03|EU123456|P|2.5
PID|1||EU001^^^LOCAL||MOREAU^CLAIRE||1980|F|||14 RUE DES TILLEULS^2 ETAGE^TOURS^^||+33XXXXXXXXXX|||M
PV1|1|I|CARDIO^101^1||||DRMED^PIERRE|||||||||||V|||||202409071200|202409091015""",
        "ocr_style": """COMPTE RENDU DE CONSULTATION
Service de médecine interne
Nom du patient : Julien Bernard
Adresse déclarée : 7 avenue Victor Hugo, Lyon
Date de la consultation : 04/12/2024
Motif : fatigue persistante et troubles du sommeil depuis plusieurs mois.
Le patient indique être récemment séparé et avoir changé de domicile au cours de l’année. Il exerce une activité de cadre commercial impliquant des déplacements fréquents entre Lyon et Genève.
Antécédents signalés lors de l’entretien :
– Épisode dépressif léger en 2020
– Suivi médical antérieur dans un autre établissement de la région
Recommandations :
– Bilan complémentaire
– Réévaluation de la situation professionnelle
– Consultation de suivi prévue courant janvier 2025
Document établi pour transmission au médecin traitant."""
    },
    
    "india_dpdp": {
        "structured_json": {
            "patient": {
                "fullName": "Anita Kulkarni",
                "gender": "female",
                "dateOfBirth": "1976-09-08",
                "address": {
                    "line1": "House No. 17, Sai Krupa Layout",
                    "area": "Yelahanka",
                    "city": "Bengaluru",
                    "state": "Karnataka",
                    "postalCode": "560064"
                },
                "identifiers": {"aadhaar": "7421-8834-9912", "pan": "BKTPK8821L"},
                "contact": {"mobile": "+91-9XXXXXX432"}
            },
            "encounter": {
                "admissionDate": "2024-10-03",
                "dischargeDate": "2024-10-06",
                "reason": "Acute exacerbation of chronic asthma"
            }
        },
        "unstructured_discharge": {
            "patient_name": "Ravi Shankar Mehta",
            "age": 52,
            "address": "Flat 402, Shanti Residency, 6th Cross Road, Indiranagar, Bengaluru -- 560038",
            "admission_date": "18/11/2024",
            "discharge_date": "22/11/2024",
            "pan": "FGHPM4732Q",
            "aadhaar_mobile_ending": "8821",
            "diagnosis": "elevated blood pressure and abnormal ECG findings",
            "past_medical_history": ["Hypertension (2018)", "Type 2 diabetes mellitus (6 years)"],
            "employment": "regional sales manager with a private logistics firm",
            "family": "lives with spouse and two children"
        },
        "semi_structured": {
            "patient_name": "Suresh Nair",
            "age": 61,
            "gender": "Male",
            "address": "Plot No. 88, Lake View Road, Vyttila, Kochi -- 682019, Kerala",
            "aadhaar": "5632 9912 4478",
            "admission_date": "05/12/2024",
            "discharge_date": "09/12/2024",
            "complaint": "Fever with generalized weakness and loss of appetite for 5 days",
            "occupation": "retired bank employee"
        },
        "hl7_v2_adt": """MSH|^~\\&|HospitalSys|BLR_HOSP|CareApp|STATE_HEALTH|202412151030||ADT^A03|DPDP445812|P|2.5
PID|1||IND998721^^^LOCAL||KUMAR^RAJESH||19720322|M|||12A MG Road^Near Metro Station^Bengaluru^KA^560001||+9198XXXX112|||M||AADHAAR^998877665544
PV1|1|I|MEDWARD^301^1|||DRSEN^ANITA|||||||||||VN20241215
DG1|1||I10|Essential (primary) hypertension|20241215|F
OBX|1|TX|NOTE||Patient employed in private manufacturing unit. PAN verified during billing.||""",
        "ocr_style": """DISCHARGE RECORD – GENERAL MEDICINE

Patient Name: Suresh Nair
Age: 61
Gender: Male

Residential Address:
Plot No. 88, Lake View Road,
Vyttila, Kochi – 682019, Kerala

Government ID Provided:
Aadhaar No: 5632 9912 4478

Admission Date: 05/12/2024
Discharge Date: 09/12/2024

Primary Complaint:
Fever with generalized weakness and loss of appetite for 5 days.

Clinical Notes:
Patient is a retired bank employee living with spouse. No recent travel history. Blood investigations showed elevated inflammatory markers. Dengue NS1 negative. Managed conservatively with IV fluids and antipyretics.

Past Medical History:
Hypertension since 2015.

Medications on Discharge:
Telmisartan 40 mg once daily
Paracetamol as required

Follow-up:
Review after 7 days at local physician clinic.

Emergency Contact:
Wife – Latha Nair
Mobile: 9XXXXXX218"""
    },
    
    "base_cases": {
        "json": {
            "patient": {
                "name": "Alex Morgan",
                "ageGroup": "adult",
                "residenceType": "shared housing"
            },
            "encounter": {
                "reasonForVisit": "persistent fatigue and dizziness",
                "clinicalFindings": ["mild anemia", "low-normal blood pressure"],
                "history": {
                    "lifestyleFactors": ["work-related stress", "irregular sleep"],
                    "familyHistory": "cardiovascular illness in a parent"
                }
            },
            "treatment": {"interventions": ["intravenous fluids", "nutritional supplementation"]},
            "discharge": {
                "condition": "stable",
                "recommendations": ["maintain hydration", "balanced diet", "outpatient follow-up"]
            }
        },
        "unstructured": """DISCHARGE NOTE

The patient, identified as Alex Morgan, was admitted earlier this month for evaluation of persistent fatigue and intermittent dizziness. The patient is an adult and resides in a shared residential complex near the city center.

Clinical assessment revealed mild anemia and borderline low blood pressure readings. The patient reported increased workload-related stress and irregular sleep patterns over the past several weeks. Family history includes a parent with a history of cardiovascular disease later in life.

At discharge, the patient was advised to maintain adequate hydration, follow a balanced diet, and schedule an outpatient follow-up visit.""",
        "structured_text": {
            "patient_name": "Alex Morgan",
            "age_group": "Adult",
            "living_situation": "Shared residence",
            "reason_for_visit": "Fatigue and dizziness",
            "clinical_findings": ["Mild anemia", "Low-normal blood pressure"],
            "relevant_history": ["Work-related stress", "Irregular sleep schedule", "Family history of cardiovascular illness"],
            "treatment": ["Intravenous fluids", "Nutritional support"],
            "discharge_condition": "Stable"
        },
        "hl7_v2_adt": """MSH|^~\\&|EHRSystem|GLOBAL|ADTService|GLOBAL|202501011030||ADT^A03|BASE123456|P|2.5
PID|1||BASE001^^^LOCAL||MORGAN^ALEX||19800101|||M|||SHARED RESIDENCE^NEAR CITY CENTER^^^||+1XXXXXXXXXX|||M
PV1|1|I|MED^101^1||||||||||||V|||||202501011200|202501031015""",
        "ocr_style": """GENERAL HEALTH CENTER
Scanned Discharge Form

Patient: Alex Morgan
Age Group: Adult
Residence: Shared complex

Admission: Recent month
Reason: Fatigue and dizziness

Findings: Mild anemia, low BP

History: Stress, poor sleep, family CV history

Discharge: Stable
Notes: Hydration, diet, follow-up
Signature: [illegible]"""
    }
}


def get_all_cases():
    """Return all demo cases"""
    return demo_cases


def get_cases_by_regulation(regulation):
    """
    Get cases by regulation type
    
    Args:
        regulation (str): One of 'hipaa', 'lgpd', 'uk_gdpr', 'eu_gdpr', 'india_dpdp', 'base_cases'
    
    Returns:
        dict: Cases for the specified regulation
    """
    return demo_cases.get(regulation.lower(), {})


def get_all_patient_names():
    """Extract all patient names from the demo cases"""
    names = []
    
    # HIPAA cases
    names.append(demo_cases["hipaa"]["structured_discharge_summary"]["patient_name"])
    names.append(demo_cases["hipaa"]["json_fhir"]["name"][0]["given"][0] + " " + 
                 demo_cases["hipaa"]["json_fhir"]["name"][0]["family"])
    
    # LGPD cases
    names.append(demo_cases["lgpd"]["json_fhir"]["name"][0]["given"][0] + " " + 
                 demo_cases["lgpd"]["json_fhir"]["name"][0]["family"])
    names.append(demo_cases["lgpd"]["structured_text"]["nome"])
    
    # UK GDPR
    names.append(demo_cases["uk_gdpr"]["json_fhir"]["name"][0]["given"][0] + " " + 
                 demo_cases["uk_gdpr"]["json_fhir"]["name"][0]["family"])
    names.append(demo_cases["uk_gdpr"]["structured_referral"]["patient_name"])
    
    # India DPDP
    names.append(demo_cases["india_dpdp"]["unstructured_discharge"]["patient_name"])
    names.append(demo_cases["india_dpdp"]["structured_json"]["patient"]["fullName"])
    names.append(demo_cases["india_dpdp"]["semi_structured"]["patient_name"])
    
    # Base cases
    names.append(demo_cases["base_cases"]["structured_text"]["patient_name"])
    
    return names


if __name__ == "__main__":
    # Example usage
    print("Demo Cases Loaded Successfully")
    print(f"\nAvailable regulations: {list(demo_cases.keys())}")
    print(f"\nTotal patient names: {len(get_all_patient_names())}")
    print("\nSample patient names:")
    for name in get_all_patient_names()[:5]:
        print(f"  - {name}")