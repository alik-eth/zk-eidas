export interface CredentialRequirement {
  role: string          // e.g. 'buyer', 'seller', 'student', 'holder'
  roleLabelKey: string  // i18n key for display
  credentialType: string
  predicateIds: string[]
  disclosedField: string
  nullifierField?: string
}

export interface HolderBinding {
  roleA: string              // role of first credential (e.g. 'seller')
  roleB: string              // role of second credential (e.g. 'vehicle')
  claimA: string             // claim name in credential A (e.g. 'document_number')
  claimB: string             // claim name in credential B (e.g. 'owner_document_number')
  labelKey: string           // i18n key for display
}

export interface ContractTemplate {
  id: string
  titleKey: string
  descKey: string
  bodyKey_en: string
  bodyKey_uk: string
  icon: string
  credentials: CredentialRequirement[]
  bindings?: HolderBinding[]
}

export const CONTRACT_TEMPLATES: ContractTemplate[] = [
  {
    id: 'age_verification',
    titleKey: 'contracts.ageVerification.title',
    descKey: 'contracts.ageVerification.desc',
    bodyKey_en: 'contracts.ageVerification.body_en',
    bodyKey_uk: 'contracts.ageVerification.body_uk',
    icon: '🔞',
    credentials: [
      {
        role: 'holder',
        roleLabelKey: 'contracts.role.holder',
        credentialType: 'pid',
        predicateIds: ['age'],
        disclosedField: 'document_number',
        nullifierField: 'document_number',
      },
    ],
  },
  {
    id: 'student_transit',
    titleKey: 'contracts.studentTransit.title',
    descKey: 'contracts.studentTransit.desc',
    bodyKey_en: 'contracts.studentTransit.body_en',
    bodyKey_uk: 'contracts.studentTransit.body_uk',
    icon: '🎓',
    credentials: [
      {
        role: 'student',
        roleLabelKey: 'contracts.role.student',
        credentialType: 'student_id',
        predicateIds: ['active_student'],
        disclosedField: 'student_number',
        nullifierField: 'student_number',
      },
    ],
  },
  {
    id: 'driver_employment',
    titleKey: 'contracts.driverEmployment.title',
    descKey: 'contracts.driverEmployment.desc',
    bodyKey_en: 'contracts.driverEmployment.body_en',
    bodyKey_uk: 'contracts.driverEmployment.body_uk',
    icon: '🚛',
    credentials: [
      {
        role: 'driver',
        roleLabelKey: 'contracts.role.driver',
        credentialType: 'drivers_license',
        predicateIds: ['valid', 'category_b', 'experienced'],
        disclosedField: 'license_number',
        nullifierField: 'license_number',
      },
    ],
  },
  {
    id: 'vehicle_sale',
    titleKey: 'contracts.vehicleSale.title',
    descKey: 'contracts.vehicleSale.desc',
    bodyKey_en: 'contracts.vehicleSale.body_en',
    bodyKey_uk: 'contracts.vehicleSale.body_uk',
    icon: '🚗',
    credentials: [
      {
        role: 'seller',
        roleLabelKey: 'contracts.role.seller',
        credentialType: 'pid',
        predicateIds: ['age'],
        disclosedField: 'document_number',
        nullifierField: 'document_number',
      },
      {
        role: 'vehicle',
        roleLabelKey: 'contracts.role.vehicleReg',
        credentialType: 'vehicle',
        predicateIds: ['insured', 'vin_active'],
        disclosedField: 'vin',
      },
      {
        role: 'buyer',
        roleLabelKey: 'contracts.role.buyer',
        credentialType: 'pid',
        predicateIds: ['age'],
        disclosedField: 'document_number',
        nullifierField: 'document_number',
      },
    ],
    bindings: [
      {
        roleA: 'seller',
        roleB: 'vehicle',
        claimA: 'document_number',
        claimB: 'owner_document_number',
        labelKey: 'contracts.binding.sellerOwnsVehicle',
      },
    ],
  },
]
