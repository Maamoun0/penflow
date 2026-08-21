---
trigger: always_on
---

# Flutter Project Rules

## Architecture: Clean Architecture (Mandatory)

lib/
├── core/
│   ├── constants/
│   ├── errors/
│   ├── extensions/
│   ├── theme/
│   └── utils/
├── features/
│   └── feature_name/
│       ├── data/
│       │   ├── datasources/
│       │   ├── models/
│       │   └── repositories/  ← implementations
│       ├── domain/
│       │   ├── entities/
│       │   ├── repositories/  ← interfaces
│       │   └── usecases/
│       └── presentation/
│           ├── providers/
│           ├── screens/
│           └── widgets/
└── main.dart

Rules:
- NEVER put business logic in widgets or screens
- NEVER call APIs directly from presentation layer
- Domain layer must have ZERO Flutter/external dependencies
- All external data access through Repository interfaces only
- One UseCase = one action, nothing more

## State Management: Riverpod (Only)
- AsyncNotifierProvider for async state
- NotifierProvider for sync state  
- Provider for computed/derived values
- NEVER use setState() except for isolated local UI state
- All providers in providers/ folder inside each feature

## Naming Conventions
- Screens: HomeScreen, ProfileScreen
- Widgets: UserAvatarWidget, ProductCardWidget
- Providers: userProvider, authStateProvider
- Notifiers: AuthNotifier, CartNotifier
- Repository interface: UserRepository
- Repository implementation: UserRepositoryImpl
- UseCases: GetUserUseCase, LoginUseCase
- Data model: UserModel | Domain entity: User

## Network Layer
- Use Dio — always wrapped in a datasource class
- API response → Model (data layer) → Entity (domain layer)
- Handle HTTP errors at data layer
- Throw domain-level exceptions upward
- Never expose raw API responses to domain or presentation

## Navigation
- Use GoRouter
- All routes in one centralized router file

## Performance
- Use const constructors everywhere possible
- Scope providers tightly — avoid rebuilding large trees
- ListView.builder for ALL lists — never map-to-children

## Testing (Required per Feature)
- Unit test: every UseCase
- Unit test: every Repository implementation
- Widget test: every screen (render + interaction)