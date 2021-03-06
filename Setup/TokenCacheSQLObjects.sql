USE [ReportServer]
GO
/****** Object:  Schema [extended]    Script Date: 1/22/2020 12:01:02 PM ******/
CREATE SCHEMA [extended]
GO
/****** Object:  Table [extended].[UserTokenCache]    Script Date: 1/22/2020 12:01:02 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [extended].[UserTokenCache](
	[UserTokenCacheId] [int] IDENTITY(1,1) NOT NULL,
	[ClientId] [varchar](512) NULL,
	[UserId] [varchar](512) NULL,
	[Resource] [varchar](512) NULL,
	[CacheBits] [varbinary](max) NULL,
	[LastWrite] [datetime2](7) NULL,
 CONSTRAINT [PK_UserTokenCache] PRIMARY KEY CLUSTERED 
(
	[UserTokenCacheId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY],
 CONSTRAINT [UQ_UserTokenCache] UNIQUE NONCLUSTERED 
(
	[ClientId] ASC,
	[UserId] ASC,
	[Resource] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  StoredProcedure [extended].[AddUserToken]    Script Date: 1/22/2020 12:01:02 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [extended].[AddUserToken]
	@ClientId varchar(512),
	@UserId varchar(512),
	@Resource varchar(512),
	@CachedBits [varbinary](max),
	@LastWrite [DateTime2],
	@UserTokenCacheId int OUTPUT
AS
BEGIN
	SET NOCOUNT ON;

    insert into extended.UserTokenCache (
		[ClientId],
		[UserId],
		[Resource],
		[CacheBits],
		[LastWrite]
	)
	values (
		@ClientId,
		@UserId,
		@Resource,
		@CachedBits,
		@LastWrite
	)

	SET @UserTokenCacheId = SCOPE_IDENTITY()
END
GO
/****** Object:  StoredProcedure [extended].[ClearUserToken]    Script Date: 1/22/2020 12:01:02 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [extended].[ClearUserToken]
	@ClientId varchar(512),
	@UserId varchar(512),
	@Resource varchar(512)
AS
BEGIN
	SET NOCOUNT ON;

    delete
	from
		extended.UserTokenCache
	where
		ClientId = @ClientId
	AND	UserId = @UserId
	AND	Resource = @Resource
END
GO
/****** Object:  StoredProcedure [extended].[GetUserToken]    Script Date: 1/22/2020 12:01:02 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [extended].[GetUserToken]
	@ClientId varchar(512),
	@UserId varchar(512),
	@Resource varchar(512)
AS
BEGIN
	SET NOCOUNT ON;

    select
		UserTokenCacheId,
		CacheBits,
		LastWrite
	from
		extended.UserTokenCache
	where
		ClientId = @ClientId
	AND	UserId = @UserId
	AND	Resource = @Resource
END
GO
/****** Object:  StoredProcedure [extended].[GetUserTokenLastWrite]    Script Date: 1/22/2020 12:01:02 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [extended].[GetUserTokenLastWrite]
	@ClientId varchar(512),
	@UserId varchar(512),
	@Resource varchar(512)
AS
BEGIN
	SET NOCOUNT ON;

    select
		LastWrite
	from
		extended.UserTokenCache
	where
		ClientId = @ClientId
	AND	UserId = @UserId
	AND	Resource = @Resource
END
GO
/****** Object:  StoredProcedure [extended].[UpdateUserToken]    Script Date: 1/22/2020 12:01:02 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [extended].[UpdateUserToken]
	@UserTokenCacheId int,
	@CachedBits [varbinary](max),
	@LastWrite [DateTime2]
AS
BEGIN
	SET NOCOUNT ON;

    UPDATE extended.UserTokenCache
	SET
		[CacheBits] = @CachedBits,
		[LastWrite] = @LastWrite
	WHERE
		UserTokenCacheId = @UserTokenCacheId
END
GO
